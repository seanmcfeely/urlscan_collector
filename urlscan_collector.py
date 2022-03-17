#!/usr/bin/env python3

import asyncio
import aiohttp
import argparse
import configparser
import datetime
import glob
import json
import logging
import logging.config
import os
import pysip
import sys
import traceback

from typing import List
from urllib.parse import urlparse

from urlscanio import UrlScan

HOME_PATH = os.path.dirname(os.path.abspath(__file__))

STORED_DIR_NAME = "incoming_results"
STORED_DIR = os.path.join(HOME_PATH, STORED_DIR_NAME)

PROBLEM_INDICATORS = 'problem_indicators'

REQUIRED_DIRS = [STORED_DIR, PROBLEM_INDICATORS, "logs", "var"]


for path in [os.path.join(HOME_PATH, x) for x in REQUIRED_DIRS]:
    if not os.path.isdir(path):
        try:
            os.mkdir(path)
        except Exception as e:
            sys.stderr.write("ERROR: cannot create directory {0}: {1}\n".format(path, str(e)))
            sys.exit(1)

def write_error_report(message):
    """Record unexpected errors."""
    logging.error(message)
    traceback.print_exc()

    try:
        output_dir = "error_reporting"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(
            os.path.join(output_dir, datetime.datetime.now().strftime("%Y-%m-%d:%H:%M:%S.%f")),
            "w",
        ) as fp:
            fp.write(message)
            fp.write("\n\n")
            fp.write(traceback.format_exc())

    except Exception as e:
        traceback.print_exc()


def create_timedelta(timespec):
    """Utility function to translate DD:HH:MM:SS into a timedelta object."""
    duration = timespec.split(":")
    seconds = int(duration[-1])
    minutes = 0
    hours = 0
    days = 0

    if len(duration) > 1:
        minutes = int(duration[-2])
    if len(duration) > 2:
        hours = int(duration[-3])
    if len(duration) > 3:
        days = int(duration[-4])
    return datetime.timedelta(days=days, seconds=seconds, minutes=minutes, hours=hours)


def get_incoming_result_paths():
    return glob.glob(f"{os.path.join(STORED_DIR)}/*.json")


def load_result(result_path: str):
    with open(result_path, "r") as fp:
        data = json.load(fp)
    return data

def create_sip_indicator(sip: pysip.pysip.Client, data: dict):
    """Create a SIP indicator.
    
    Args:
      sip: A pysip client.
      data: Dictionary representation of a sip indicator you want to create.
    Returns:
      The unique ID of the SIP indicator that was created or False.
    """
    logging.info(f"Attempting to create SIP indicator with following data: {data}")
    if not data['value']:
        logging.error(f"proposed indicator value is empty.")
        return False

    try:
        result = sip.post('/api/indicators', data)
        if 'id' in result:
            logging.info(f"created SIP indicator {result['id']} : {result}")
            return result['id']
    except pysip.ConflictError as e:
        logging.info(f"{e} : SIP indicator already exists with value: {data['value']}")
        raise e
    except pysip.RequestError as e:
        if "is too long" in str(e):
            logging.warning("SIP indicator value is too long. Truncating.")
            data['value'] = data['value'][:255]
            result = sip.post('/api/indicators', data)
            if 'id' in result:
                logging.info(f"created SIP indicator {result['id']} : {result}")
                return result['id']
    except Exception as e:
        # this should never happen
        reference_id = json.loads(data['references'][0]['reference'])['_id']
        indicator_file = f"{reference_id}.json"
        save_path = os.path.join(HOME_PATH, PROBLEM_INDICATORS, indicator_file)
        with open(save_path, 'w') as fp:
            json.dump(data, fp)
        logging.error(f"unidentified problem creating SIP indicator. saved indicator to {save_path}: {e}")
        write_error_report(f"unidentified problem creating SIP indicator. saved indicator to {save_path}: {e}")

    return False

def format_indicator_for_sip(type: str, 
                       value: str,
                       reference: dict,
                       tags: list,
                       username: str,
                       case_sensitive=False) -> dict:
        # A sip indicator with some defaults defined.
        if not tags or not isinstance(tags, list):
            tags = []
        if "UrlScan" not in tags:
            tags.append("UrlScan")
        return { 'type':type,
                 'status': 'New',
                 'confidence': 'low',
                 'impact' : 'medium',
                 'value' : value,
                 'references' : [ {'source':"UrlScan", 'reference': json.dumps(reference)}],
                 'username' :username,
                 'case_sensitive': case_sensitive,
                 'tags': list(set(tags))
                }

async def collect(config):

    # variables
    now = datetime.datetime.utcnow()
    start_time = None
    end_datetime = now
    end_time = end_datetime.strftime("%Y-%m-%dT%H:%M:%S")

    # default initial days to collect IOCs is 10
    initial_range = create_timedelta(config["collection_settings"].get("initial_range", "10:00:00:00"))
    # default maximun days to collect IOCs over is 30
    max_time_range = create_timedelta(
        config["collection_settings"].get("maximum_time_range", "30:00:00:00")
    )  # safe guard
    last_search_time_file = os.path.join(HOME_PATH, "var", f"last_search_time")
    if not os.path.exists(os.path.join(last_search_time_file)):
        logging.info(f"{last_search_time_file} doesn't exist. Setting start time to {initial_range}.")
        start_datetime = now - initial_range
        start_time = start_datetime.strftime("%Y-%m-%dT%H:%M:%S")
    else:
        try:
            with open(last_search_time_file, "r") as fp:
                start_time = fp.read()
            start_datetime = datetime.datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%S")
            logging.debug(f"last successful search end time: {start_time}")
        except Exception as e:
            logging.error(str(e))
            return False

    if (end_datetime - start_datetime) > max_time_range:
        logging.warning(
            f"it appears this collector hasn't executed in a really long time. Adjusting time frame to {max_time_range}"
        )
        start_datetime = end_datetime - max_time_range
        start_time = start_datetime.strftime("%Y-%m-%dT%H:%M:%S")
        logging.info(f"start time adjusted to {start_time}")

    # max_indicators_per_day - keep a throttle on indicators created per day
    indicators_created_today = 0
    max_indicators_per_day = config['collection_settings'].getint('max_indicators_per_day')
    indicator_creation_count_file = os.path.join(HOME_PATH, 'var', f"indicator_count_for_{datetime.datetime.now().strftime('%Y-%m-%d')}")
    if not os.path.exists(indicator_creation_count_file):
        logging.info(f"reseting indicator count for a new day..")
        for old_file in glob.glob(f"{os.path.join(HOME_PATH, 'var')}/indicator_count_for_*"):
            logging.info(f"deleting old variable file: {old_file}")
            os.remove(old_file)
        with open(indicator_creation_count_file, 'w') as f:
            f.write(str(0))
    else:
        with open(indicator_creation_count_file, 'r') as f:
            indicators_created_today = f.read()
        indicators_created_today = int(indicators_created_today)

    if indicators_created_today >= max_indicators_per_day:
        logging.error(f"maximum indicators already created for the day.")

    # connect to sip
    sip = config["sip"].getboolean("enabled")
    if sip:
        verify_ssl = config['sip'].get('verify_ssl')
        if not os.path.exists(verify_ssl):
            verify_ssl=config['sip'].getboolean('verify_ssl')
        sip = pysip.Client(f"{config['sip'].get('server')}:{config['sip'].get('port')}", config['sip']['api_key'], verify=verify_ssl)
    create_domain_name_indicators_from_payload_urls = config["sip"].getboolean("create_domain_name_indicators_from_payload_urls")


    # For filtering IOCs by malware, confidence_level, submitter, etc.
    urlscan_collection_filter = config["urlscan_collection_filter"]
    base_query = urlscan_collection_filter.get("base_query")
    not_query = urlscan_collection_filter.get("not_query")

    # map UrlScan IOCs to SIP IOCs
    sip_map = config['sip_mappings']

    # urlscan connection & collection settings
    api_key = config["urlscan"].get("api_key") if config["urlscan"].get("api_key") else None
    api_url = config["urlscan"].get("url") if config["urlscan"].get("url") else None
    proxy = config["urlscan"].get("proxy") if config["urlscan"].get("proxy") else None

    # track indicators created and stored by this execution.
    indicators_created = 0
    indicators_stored = 0

    # collection variables
    store_only = config["collection_settings"].getboolean("store_only")
    process_from_storage_only = config["collection_settings"].getboolean("process_from_storage_only")
    result_size_per_request = config["collection_settings"].getint("max_result_size_per_request", 1000)
    process_this_stored_result_only = False
    if "process_this_stored_result_only" in config["collection_settings"]:
        process_this_stored_result_only = config["collection_settings"].get("process_this_stored_result_only")

    def _create_sip_indicators_from_urlscan_result(result):
        # post to SIP. We make two indicators per results, a URL and a domain name.
        # Actually, it's possible the page came from a different URL which can be seen in the task data.
        # We could make indicators for the task url and domain as well, if they're different.
        # - We could also only do this for a list of brands that we care about, like Microsoft, etc.
        reference = {}
        reference['_id'] = result['_id']
        reference['result_document'] = result['result']
        reference['gui_link'] = f"https://urlscan.io/result/{result['_id']}"
        reference['brand'] = [brand['name'] for brand in result['brand']]
        reference['task_time'] = result['task']['time']

        tags = []
        if "source" in result["task"]:
            # means that result["task"]["method"] should be "automatic"
            tags.append(result["task"]["source"])
        for brand in result["brand"]:
            tags.append(brand['name'])

        # create the indicators
        indicator_data = []
        itype = sip_map["domain"]
        ivalue = result["page"]["domain"]
        idata = format_indicator_for_sip(type=itype, value=ivalue, reference=reference, tags=tags, username=config['sip'].get('user'))
        indicator_data.append(idata)

        itype = sip_map["url"]
        ivalue = result["page"]["url"]
        idata = format_indicator_for_sip(type=itype, value=ivalue, reference=reference, tags=tags, username=config['sip'].get('user'))
        indicator_data.append(idata)

        sip_results = []
        for idata in indicator_data:
            try:
                sip_result = create_sip_indicator(sip, idata) if sip else None
            except pysip.ConflictError:
                continue
            if sip_result:
                logging.info(f"created sip indictor ID={sip_result}")
                sip_results.append(sip_result)

        return sip_results

    # Check for incoming results that still need to be processing.
    if not store_only:
        result_paths = get_incoming_result_paths()
        if process_this_stored_result_only:
            result_paths = [rp for rp in result_paths if process_this_stored_result_only in rp]
        logging.info(f"Found {len(result_paths)} stored results ...")
        if result_paths:
            iocs_from_storage = 0
            for result_path in result_paths:
                logging.debug(f"Processing {result_path}...")
                result = load_result(result_path)
                # post to SIP
                if indicators_created_today < max_indicators_per_day:
                    sip_results = _create_sip_indicators_from_urlscan_result(result)
                    if sip_results:
                        indicators_created += len(sip_results)
                        indicators_created_today += len(sip_results)
                        os.remove(result_path)
                else:
                    logging.warning(f"maximum indicators created for the day.")
        if process_this_stored_result_only:
            return True

    if not process_from_storage_only:
        # get urls from urlscan
        total_results_collected = 0
        connection_kwargs = {'proxy': proxy} if proxy else {}
        async with UrlScan(api_key=api_key, api_url=api_url, **connection_kwargs) as urlscan:
            logging.info(f"Collecting urlscan.io phishfeed results from {start_time} to {end_time} ...")
            query = f"{base_query} date:[{start_time} TO {end_time}] NOT ({not_query})"

            # As of writing this, the results are always sorted newest to oldest.
            # If the has_more flag is set, we use the `sort` variable of the oldest result to get the next batch
            # of older results. So we will break out of the while loop when we have all the results.
            search_after = None
            collecting = True
            while collecting:
                logging.info(f"urlscan.io collection search query: {query} size: {result_size_per_request} search_after: {search_after}")
                results = await urlscan.search(query, size=result_size_per_request, search_after=search_after)
                if not results:
                    logging.info(f"no results collected.")
                    return None
                total_results = results.get("total")
                more_results = results.get("has_more")
                results = results.get("results")
                if not results:
                    logging.info(f"no results were returned.")
                    collecting = False
                total_results_collected += len(results)
                outstanding_results = total_results - total_results_collected
                logging.info(f"got {total_results_collected} out of {total_results} reported results, with more_results={more_results}")
                for result in results:
                    scan_id = result.get("_id")
                    logging.debug(f"obtained new urlscan result: {scan_id}")

                    # for continuing the search as needed if we don't break out of the while loop.
                    search_after = f"{result['sort'][0]},{result['sort'][1]}" 

                    if store_only:
                        with open(os.path.join(STORED_DIR, f"{scan_id}.json"), "w") as fp:
                            fp.write(json.dumps(result))
                            indicators_stored += 1
                        continue

                    sip_results = False
                    if indicators_created_today < max_indicators_per_day:
                        sip_results = _create_sip_indicators_from_urlscan_result(result)
                        if sip_results:
                            indicators_created += len(sip_results)
                            indicators_created_today += len(sip_results)
                    else:
                        logging.warning(f"maximum indicators created for the day.")

                    if not sip_results:
                        # SIP post failed or max indicators created for the day, write locally to get picked back up later.
                        with open(os.path.join(STORED_DIR, f"{scan_id}.json"), "w") as fp:
                            fp.write(json.dumps(result))
                            indicators_stored += 1

                if more_results or outstanding_results > 0:
                    logging.info(f"{outstanding_results} results still outstanding...")    
                    if not more_results and outstanding_results < result_size_per_request and outstanding_results == last_outstanding_results:
                        logging.warning(f"{outstanding_results} results still outstanding, but we have no more results to get...")
                        logging.info(f"breaking out of while loop.")
                        collecting = False
                    # track the last outstanding results to see if we need to break out of the while loop.
                    last_outstanding_results = outstanding_results         
                else:
                    collecting = False

    logging.info(f" Created {indicators_created} SIP indicators. Stored {indicators_stored} in {STORED_DIR_NAME}.")

    # If here, we consider the collection a success and update our variables.
    try:
        if not process_from_storage_only:
            # if we actually collected new results.
            with open(last_search_time_file, "w") as fp:
                fp.write(end_time)
    except Exception as e:
        write_error_report(f"Problem writing last time file: {e}")
        return False
    try:
        with open(indicator_creation_count_file, 'w') as fp:
            fp.write(str(indicators_created_today))
    except Exception as e:
        logging.error(f"Problem writing indicator count file: {e}")


async def main():

    parser = argparse.ArgumentParser(description="UrlScan PhishFeed collector.")
    parser.add_argument(
        "--logging-config",
        required=False,
        default="etc/logging.ini",
        dest="logging_config",
        help="Path to logging configuration file.  Defaults to etc/logging.ini",
    )
    parser.add_argument(
        "-c",
        "--config",
        required=False,
        default="etc/config.ini",
        dest="config_path",
        help="Path to configuration file.  Defaults to etc/config.ini",
    )
    parser.add_argument(
        "-s",
        "--store-only",
        action="store_true",
        default=False,
        help="If true, the collector will write urlscan.io results to disk and not create SIP indicators.",
    )
    parser.add_argument(
        "-pl",
        "--process-local-storage-only",
        action="store_true",
        default=False,
        help="If true, only locally stored UrlScan IOCs will be processed. UrlScan will not be queried for new IOCs.",
    )
    parser.add_argument(
        "-ptsro",
        "--process-this-stored-result-only",
        action="store",
        default=False,
        help="The path to a stored result to process only.",
    )


    args = parser.parse_args()

    # sanity check: work out of home dir
    os.chdir(HOME_PATH)

    # initialize logging
    try:
        logging.config.fileConfig(args.logging_config)
    except Exception as e:
        message = f"ERROR: unable to load logging config from {args.logging_config}: {e}"
        sys.stderr.write(message + "\n")
        write_error_report(message)
        return False

    # less verbose
    logging.getLogger("urlscan.UrlScan").setLevel(logging.INFO)

    if not os.path.exists(args.config_path):
        logging.error(f"missing config file: {args.config_path}")
        write_error_report(f"missing config file: {args.config_path}")
        return False
    config = configparser.ConfigParser()
    config.optionxform = str  # preserve case
    config.read(args.config_path)

    if args.process_local_storage_only:
        config["collection_settings"]["process_from_storage_only"] = "yes"

    if args.store_only:
        config["collection_settings"]["store_only"] = "yes"

    if args.process_this_stored_result_only:
        config["collection_settings"]["process_this_stored_result_only"] = args.process_this_stored_result_only

    await collect(config)
    return True

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        write_error_report("uncaught exception: {0}".format(str(e)))

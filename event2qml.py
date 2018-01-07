from __future__ import print_function
import os
import sys
import logging

sys.path.append(os.environ['ANTELOPE'] + "/data/python")

usage = "\n\t\tevent2qml [-h] [-v] [-d] [-p pfname] [-s XSD_schema] " \
        "database [EVID] \n"

version = '1.1'

description = """
GA adapted QuakeML export infrastructure for Antelope
---------------------------------------------------------------------------
The original quakeml export was adapted to work with GA's infrastructure.

Sudipta Basak
basaks@gmail.com
---------------------------------------------------------------------------

Original QuakeML export infrastructure for Antelope
---------------------------------------------------------------------------
This code attempts to convert 1 (or more) seismic event(s) and all
other associated information from an Antelope Datascope database
into QuakeML format. We start with an EVIDs and all ORIDs associated
to that EVID. For this we *most* have an event table present.

The XSD files describing the schema are included in the distro
and referenced in the parameter file. There are validators that
you can use to verify your exports.

The code will send all output to STDOUT or to a file if you are
using the -o FILENAME flag at runtime. Run with an EVID to export
that single event. Need to develop a method to convert all events
in a database.

Juan Reyes
reyes@ucsd.edu

Original QuakeML translation:
    https://github.com/NVSeismoLab/qmlutil
    Mark Williams
    Nevada Seismological Laboratory
    markwilliams@seismo.unr.edu


XML parser:
    XMLTODICT.PY = Parse the given XML input and convert it into a dictionary.
    #Copyright (C) 2012 Martin Blech and individual contributors.

"""

from optparse import OptionParser

try:
    import antelope.stock as stock
    import antelope.datascope as datascope
except Exception, e:
    sys.exit("Import Error: [%s] Do you have ANTELOPE installed?" % e)

try:
    from export_events.logging_helper import getLogger
    from export_events.functions import open_verify_pf, safe_pf_get
    from export_events.event import Event
    from export_events.css2qml import css2qml
    from export_events.xmltodict import *
except Exception, e:
    sys.exit("[%s] Error loading  qml functions." % e)

try:
    from lxml import etree
    validation = True
except Exception, e:
    validation = False

MODE = 'w'
log = logging.getLogger(__name__)


def event_xml(event_id, event, quakeml, output_file):
    # Get event information from Antelope
    log.info('Load information for event:[%s]' % event_id)
    event.get_event(event_id)
    # Convert the CSS3.0 schema into QuakeML format
    # Send all CSS database information to the QML class.
    log.info('Convert information to QuakeML format')
    quakeml.new_event(event=event)
    # Convert all qml information to XML
    results = xmlencode(quakeml.dump())
    if output_file:
        try:
            log.info('Write results to file [%s] mode:%s' % (
                output_file, MODE))

            ofile = open(output_file, MODE)
            ofile.write(results)

            ofile.close()
        except Exception, e:
            log.error('Problems writing to file [%s]=>%s' % (
                output_file, e))
    else:
        # Output to log if needed.
        log.debug('Print Event in QuakeML format')
        # This will go to STDOUT.
        print(results)

    if validation:
        log.debug('Try to validate the results:')

        valid = 'unknown'
        schema_file = os.path.join(os.environ['ANTELOPE'],
                                   '/contrib/data/quakeml/QuakeML-1.2.rng')

        log.debug('Looking for file: %s' % schema_file)

        if not os.path.exists(schema_file):
            ROOT = os.path.abspath(os.path.dirname(__file__))
            schema_file = os.path.join(ROOT + '/schemas/QuakeML-1.2.rng')

        if os.path.exists(schema_file):

            log.debug('Read file: %s' % schema_file)

            try:
                relaxng = etree.RelaxNG(file=schema_file)
                output_text = StringIO(results)
                xmldoc = etree.parse(output_text)
                valid = relaxng.validate(xmldoc)

            except Exception, e:
                log.warning("%s => %s" % (Exception, e))
                log.warning("Cannot validate.")

        else:
            log.warning('Missing schema file: %s' % schema_file)

        log.info('VALID QuakeML-1.2 ? => %s' % valid)
    else:
        log.debug('Output QuakeMl not validated.')


def setup_event2qml(options, database):
    """
    Parameters
    ----------
    options: OptionParser object

    Returns
    -------
    ev: instance of Event class
    qml: instance of QualeMl class
    logging: logging.getLogger object

    """

    log.info("database [%s]" % database)
    # Pull values from ParameterFile
    options.pf = stock.pffiles(options.pf)[-1]
    log.info("Parameter file to use [%s]" % options.pf)
    pf_object = open_verify_pf(options.pf, 1472083200)
    uri_prefix = safe_pf_get(pf_object, 'uri_prefix', 'quakeml')
    agency_uri = safe_pf_get(pf_object, 'agency_uri', 'local')
    agency_id = safe_pf_get(pf_object, 'agency_id', 'xx')
    author = safe_pf_get(pf_object, 'author', 'antelope.event2qml')
    etype_map = safe_pf_get(pf_object, 'etype_map', {})
    preferred_magtypes = safe_pf_get(pf_object, 'preferred_magtypes', [])
    Q_NAMESPACE = safe_pf_get(pf_object, 'Q_NAMESPACE',
                              'http://quakeml.org/xmlns/quakeml/1.2')
    CATALOG_NAMESPACE = safe_pf_get(pf_object, 'CATALOG_NAMESPACE',
                                    'http://anss.org/xmlns/catalog/0.1')
    BED_NAMESPACE = safe_pf_get(pf_object, 'BED_NAMESPACE',
                                'http://quakeml.org/xmlns/bed/1.2')
    BEDRT_NAMESPACE = safe_pf_get(pf_object, 'BEDRT_NAMESPACE',
                                  'http://quakeml.org/xmlns/bed-rt/1.2')
    review_flags = safe_pf_get(pf_object, 'review_flags', ['r', 'y'])
    magnitude_type_subset = safe_pf_get(pf_object,
                                        'magnitude_type_subset', ['.*'])
    info_description = safe_pf_get(pf_object, 'event_info_description', '')
    info_comment = safe_pf_get(pf_object, 'event_info_comment', '')
    append_to_output_file = stock.yesno(
        safe_pf_get(pf_object, 'append_to_output_file', 'true'))
    add_mt = stock.yesno(safe_pf_get(pf_object, 'add_mt', 'true'))
    add_origin = stock.yesno(safe_pf_get(pf_object, 'add_origin', 'true'))
    add_fplane = stock.yesno(safe_pf_get(pf_object, 'add_fplane', 'true'))
    add_stamag = stock.yesno(safe_pf_get(pf_object, 'add_stamag', 'true'))
    add_arrival = stock.yesno(safe_pf_get(pf_object, 'add_arrival', 'true'))
    add_detection = stock.yesno(safe_pf_get(pf_object, 'add_detection',
                                            'true'))
    add_magnitude = stock.yesno(safe_pf_get(pf_object, 'add_magnitude',
                                            'true'))
    mt_auth_select = filter(None, safe_pf_get(pf_object,
                                              'mt_auth_select', []))
    mt_auth_reject = filter(None, safe_pf_get(pf_object,
                                              'mt_auth_reject', []))
    event_auth_select = filter(None, safe_pf_get(pf_object,
                                                 'event_auth_select', []))
    event_auth_reject = filter(None, safe_pf_get(pf_object,
                                                 'event_auth_reject', []))
    netmag_auth_select = filter(None, safe_pf_get(pf_object,
                                                  'netmag_auth_select', []))
    netmag_auth_reject = filter(None, safe_pf_get(pf_object,
                                                  'netmag_auth_reject', []))
    fplane_auth_select = filter(None, safe_pf_get(pf_object,
                                                  'fplane_auth_select', []))
    fplane_auth_reject = filter(None, safe_pf_get(pf_object,
                                                  'fplane_auth_reject', []))
    origin_auth_select = filter(None, safe_pf_get(pf_object,
                                                  'origin_auth_select', []))
    origin_auth_reject = filter(None, safe_pf_get(pf_object,
                                                  'origin_auth_reject', []))
    arrival_auth_select = filter(
        None, safe_pf_get(pf_object, 'arrival_auth_select', []))
    arrival_auth_reject = filter(
        None, safe_pf_get(pf_object, 'arrival_auth_reject', []))
    detection_state_select = filter(
        None, safe_pf_get(pf_object, 'detection_state_select', []))
    detection_state_reject = filter(
        None, safe_pf_get(pf_object, 'detection_state_reject', []))
    # New event object
    log.info('Init Event()')
    ev = Event(database=database,
               magnitude_type_subset=magnitude_type_subset,
               event_auth_select=event_auth_select,
               event_auth_reject=event_auth_reject,
               origin_auth_select=origin_auth_select,
               origin_auth_reject=origin_auth_reject,
               arrival_auth_select=arrival_auth_select,
               arrival_auth_reject=arrival_auth_reject,
               netmag_auth_select=netmag_auth_select,
               netmag_auth_reject=netmag_auth_reject,
               detection_state_select=detection_state_select,
               detection_state_reject=detection_state_reject,
               mt_auth_select=mt_auth_select,
               mt_auth_reject=mt_auth_reject,
               fplane_auth_select=fplane_auth_select,
               fplane_auth_reject=fplane_auth_reject,
               prefor=options.prefor, orid=options.orid
               )
    # This is the primary object for the conversion. Initialize and
    # configure for all events that we want to process.
    log.info('Init QuakeML object')
    qml = css2qml(review_flags=review_flags, etype_map=etype_map,
                  uri_prefix=uri_prefix, agency_uri=agency_uri,
                  agency_id=agency_id, author=author,
                  q=Q_NAMESPACE, catalog=CATALOG_NAMESPACE,
                  bed=BED_NAMESPACE, bedrt=BEDRT_NAMESPACE,
                  info_description=info_description,
                  info_comment=info_comment,
                  add_origin=add_origin,
                  add_magnitude=add_magnitude,
                  add_fplane=add_fplane,
                  add_mt=add_mt, add_stamag=add_stamag,
                  add_arrival=add_arrival,
                  discriminator=options.discriminator)

    return ev, qml


if __name__ == '__main__':
    """
    event2qml primary exec.

    Configure the program with the listed values in the command line
    and parameter file and convert all possible events into QuakeML
    format.
    """

    #
    # Parse command line arguments and return configuration variables.
    #
    parser = OptionParser(usage=usage,
                          version="%prog " + version,
                          description=description)

    # Set schema file
    parser.add_option("-s", action="store", dest="schema",
                      default='', help="XML Schema Definition to implement")

    # Vebose output
    parser.add_option("-v", action="store_true", dest="verbose",
                      default=False, help="run with verbose output")


    # Force only preferred origin
    parser.add_option("--prefor", action="store_true", dest="prefor",
                      default=False, help="Only fetch the preferred origin")

    # Discriminator used to make sure our id-s are unique across multiple databases and hosts
    parser.add_option("--discriminator", type=str , dest="discriminator",
                      default=None, help="Use in order to ensure object id uniqueness across multiple databases and hosts")

    # Force only preferred origin
    parser.add_option("--orid", type=int, dest="orid",
                      default=None, help="Only fetch this origin")

    # Debug output
    parser.add_option("-d", action="store_true", dest="debug",
                      default=False, help="run with debug output")

    # Parameter File
    parser.add_option("-p", action="store", dest="pf",
                      default='event2qml.pf', help="parameter file to use")

    # Output file
    parser.add_option("-o", action="store", dest="output_file",
                      default=False, help="Save output to file")

    (main_options, args) = parser.parse_args()

    # If we don't have 2 arguments then exit.
    if len(args) != 2:
        parser.print_help()
        parser.error("incorrect number of arguments")

    evid = int(args[1])

    # Set log level
    log_level = 'WARNING'
    if main_options.debug:
        log_level = 'DEBUG'
    elif main_options.verbose:
        log_level = 'INFO'

    logging.basicConfig(level=logging.INFO)
    log.setLevel(level=log_level)
    log.info(parser.get_version())
    log.info('loglevel=%s' % log_level)

    ev, qml = setup_event2qml(main_options, database=args[0])
    event_xml(evid, ev, qml, main_options.output_file)

# stdlib
import pywintypes
from itertools import izip

# 3p
from win32com.client import Dispatch

# project
from checks.libs.wmi.counter_type import get_calculator, UndefinedCalculator


class CaseInsensitiveDict(dict):
    def __setitem__(self, key, value):
        super(CaseInsensitiveDict, self).__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(key.lower())

    def __contains__(self, key):
        return super(CaseInsensitiveDict, self).__contains__(key.lower())

    def get(self, key):
        return super(CaseInsensitiveDict, self).get(key.lower())


class WMISampler(object):
    """
    A fast Python WMI module.

    Headlines:
    * Built directly on top of the pywin32 extensions. Use of COM directly.
    * Compatible with Raw and Formatted Performance Data classes
        * Hold the previous/current sample taken from Raw Performance classes to compute new values.

    Original discussion thread: https://github.com/DataDog/dd-agent/issues/1952
    Credits to @TheCloudlessSky (https://github.com/TheCloudlessSky)
    """
    _wmi_locators = {}
    _wmi_connections = {}

    def __init__(self, logger, class_name, property_names, filters="", host="localhost",
                 namespace="root\\cimv2", username="", password=""):
        self.logger = logger

        # Connection information
        self.host = host
        self.namespace = namespace
        self.username = username
        self.password = password

        self.is_raw_perf_class = "_PERFRAWDATA_" in class_name.upper()

        # WMI class, properties, filters and counter types
        # Include required properties for making calculations with raw
        # performance counters:
        # https://msdn.microsoft.com/en-us/library/aa394299(v=vs.85).aspx
        if self.is_raw_perf_class:
            property_names.extend([
                "Timestamp_Sys100NS",
                "Frequency_Sys100NS",
                # IMPORTANT: To improve performance and since they're currently
                # not needed, do not include the other Timestamp/Frequency
                # properties:
                #   - Timestamp_PerfTime
                #   - Timestamp_Object
                #   - Frequency_PerfTime
                #   - Frequency_Object"
            ])
        self.class_name = class_name
        self.property_names = property_names
        self.filters = filters
        self.property_counter_types = None

        # Samples
        self.current_sample = None
        self.previous_sample = None

    def sample(self):
        """
        Compute new samples.
        """
        if self.is_raw_perf_class and not self.previous_sample:
            self.logger.debug(u"Querying for initial sample for raw performance counter.")
            self.current_sample = self._query()
        self.previous_sample = self.current_sample

        self.current_sample = self._query()

        self.logger.debug(u"Sample: {0}".format(self.current_sample))

    def __len__(self):
        """
        Return the number of WMI Objects in the current sample.
        """
        return len(self.current_sample)

    def __iter__(self):
        """
        Iterate on the current sample's WMI Objects and format the property values.
        """
        if self.is_raw_perf_class:
            # Format required
            for current_wmi_object, previous_wmi_object in \
                    izip(self.previous_sample, self.current_sample):
                yield current_wmi_object
        else:
            #  No format required
            for wmi_object in self.current_sample:
                yield wmi_object

    def __eq__(self, other):
        """
        Equality operator is based on the current sample.
        """
        return self.current_sample == other

    def __str__(self):
        """
        Stringify the current sample's WMI Objects.
        """
        return str(self.current_sample)

    def _format_property_values(self, previous, current):
        """
        Format WMI Object's RAW data based on the previous sample.

        Do not override the original WMI Object !
        """
        formatted_wmi_object = {}

        for property_name, property_raw_value in current.iteritems():
            pass

        return formatted_wmi_object

    def _get_connection(self):
        """
        Create and cache WMI connections.
        """
        connection_key = "{host}:{namespace}:{username}".format(
            host=self.host,
            namespace=self.namespace,
            username=self.username
        )

        if connection_key in self._wmi_connections:
            self.logger.debug(
                u"Using cached connection "
                u"(host={host}, namespace={namespace}, username={username}).".format(
                    host=self.host,
                    namespace=self.namespace,
                    username=self.username
                )
            )
            return self._wmi_connections[connection_key]

        self.logger.debug(
            u"Connecting to WMI server "
            u"(host={host}, namespace={namespace}, username={username}).".format(
                host=self.host,
                namespace=self.namespace,
                username=self.username
            )
        )

        locator = Dispatch("WbemScripting.SWbemLocator")
        self._wmi_locators[connection_key] = locator

        connection = locator.ConnectServer(self.host, self.namespace, self.username, self.password)
        self._wmi_connections[connection_key] = connection

        return connection

    @staticmethod
    def _format_filter(filters):
        """
        Transform filters to a comprehensive WQL `WHERE` clause.
        """
        def build_where_clause(fltr):
            """
            Recursively build `WHERE` clause.
            """
            f = fltr.pop()
            prop, value = f.popitem()

            if len(fltr) == 0:
                return "{property} = '{constant}'".format(
                    property=prop,
                    constant=value
                )
            return "{property} = '{constant}' AND {more}".format(
                property=prop,
                constant=value,
                more=build_where_clause(fltr)
            )

        if not filters:
            return ""

        return " WHERE {clause}".format(clause=build_where_clause(filters))

    def _query(self):
        """
        Query WMI using WMI Query Language (WQL) & parse the results.

        Returns: List of WMI objects
        """
        formated_property_names = ",".join(self.property_names)
        wql = "Select {property_names} from {class_name}{filters}".format(
            property_names=formated_property_names,
            class_name=self.class_name,
            filters=self._format_filter(self.filters),
        )
        self.logger.debug(u"Querying WMI: {0}".format(wql))

        try:
            # From: https://msdn.microsoft.com/en-us/library/aa393866(v=vs.85).aspx
            flag_return_immediately = 0x10  # Default flag.
            flag_forward_only = 0x20
            flag_use_amended_qualifiers = 0x20000

            query_flags = flag_return_immediately | flag_forward_only

            # For the first query, cache the qualifiers to determine each
            # propertie's "CounterType"
            includes_qualifiers = self.property_counter_types is None
            if includes_qualifiers:
                self.property_counter_types = CaseInsensitiveDict()
                query_flags |= flag_use_amended_qualifiers

            raw_results = self._get_connection().ExecQuery(wql, "WQL", query_flags)
            results = self._parse_results(raw_results, includes_qualifiers=includes_qualifiers)

        except pywintypes.com_error as ex:
            self.logger.warning(u"Failed to execute WMI query (%s)", wql, exc_info=True)
            results = []

        return results

    def _parse_results(self, raw_results, includes_qualifiers):
        """
        Parse WMI query results in a more comprehensive form.

        Returns: List of WMI objects
        ```
        [
            {
                'freemegabytes': 19742.0,
                'name': 'C:',
                'avgdiskbytesperwrite': 1536.0
            }, {
                'freemegabytes': 19742.0,
                'name': 'D:',
                'avgdiskbytesperwrite': 1536.0
            }
        ]
        ```
        """
        results = []
        for res in raw_results:
            # Ensure all properties are available. Use case-insensitivity
            # because some properties are returned with different cases.
            item = CaseInsensitiveDict()
            for prop_name in self.property_names:
                item[prop_name] = None

            for wmi_property in res.Properties_:
                # IMPORTANT: To improve performance, only access the Qualifiers
                # if the "CounterType" hasn't already been cached.
                should_get_qualifier_type = (
                    includes_qualifiers and
                    wmi_property.Name not in self.property_counter_types
                )

                if should_get_qualifier_type:

                    # Can't index into "Qualifiers_" for keys that don't exist
                    # without getting an exception.
                    qualifiers = {q.Name: q.Value for q in wmi_property.Qualifiers_}

                    # Some properties like "Name" and "Timestamp_Sys100NS" do
                    # not have a "CounterType" (since they're not a counter).
                    # Therefore, they're ignored.
                    if "CounterType" in qualifiers:
                        counter_type = qualifiers["CounterType"]
                        self.property_counter_types[wmi_property.Name] = counter_type

                        self.logger.debug(
                            u"Caching property qualifier CounterType: "
                            "{class_name}.{property_names} = {counter_type}"
                            .format(
                                class_name=self.class_name,
                                property_names=wmi_property.Name,
                                counter_type=counter_type,
                            )
                        )
                    else:
                        self.logger.debug(
                            u"CounterType qualifier not found for {class_name}.{property_names}"
                            .format(
                                class_name=self.class_name,
                                property_names=wmi_property.Name,
                            )
                        )

                try:
                    item[wmi_property.Name] = float(wmi_property.Value)
                except ValueError:
                    item[wmi_property.Name] = wmi_property.Value
            results.append(item)
        return results
from .lib_template import *
from collections  import defaultdict

class LuaSeeker(Seeker):
    """Seeker (Identifier) for lua zlib open source library."""

    # Library Name
    NAME = "lua"
    # version string marker
    VERSION_STRING = "$Lua: Lua "

    # Overridden base function
    def searchLib(self, logger):
        """Check if the open source library is located somewhere in the binary.

        Args:
            logger (logger): elementals logger instance

        Return Value:
            number of library instances that were found in the binary
        """
        key_string = "$Lua: Lua "
        version_strings = ["Lua 5.1", "Lua 5.2", "Lua 5.3", "Lua 5.4"]
        version_maps = {
            "Lua 5.1": "$Lua: Lua 5.1.4",
            "Lua 5.2": "$Lua: Lua 5.2.3",
            "Lua 5.3": "$Lua: Lua 5.3.6",
            "Lua 5.4": "$Lua: Lua 5.4.6"
        }
        error_strings = ["ipairs", "pairs", "coroutine", "__gc", "__tostring", "__close"]
        key_error_strings = [error_strings[0], error_strings[-1]]
        matched_error_strings = defaultdict(list)

        # Now search
        self._version_strings = []
        for bin_str in self._all_strings:
            # we have a match
            if key_string in str(bin_str):
                copyright_string = str(bin_str)
                # check for the inner version string
                if self.VERSION_STRING not in copyright_string:
                    # false match
                    continue
                # valid match
                logger.debug(f"Located a copyright string of {self.NAME} in address 0x{bin_str.ea:x} :{copyright_string}")
                # save the string for later
                self._version_strings.clear()
                self._version_strings.append(copyright_string)
            elif len(self._version_strings) == 0 and str(bin_str) in version_strings:
                logger.debug(f"Located a version string of {self.NAME} in address 0x{bin_str.ea:x}")
                self._version_strings.append(version_maps[str(bin_str)])
            # use the error strings as backups
            elif str(bin_str) in key_error_strings and len(self._version_strings) == 0:
                logger.debug(f"Located a key error string of {self.NAME} in address 0x{bin_str.ea:x}")
                matched_error_strings[str(bin_str)].append(bin_str)

        # check if we need the backup
        if len(self._version_strings) == 0 and len(list(matched_error_strings.keys())) == len(key_error_strings):
            logger.debug("We found the library, however we can't resolve its version :(")
            self._version_strings = [self.VERSION_UNKNOWN]

        # return the result
        return len(self._version_strings)

    # Overridden base function
    def identifyVersions(self, logger):
        """Identify the version(s) of the library (assuming it was already found).

        Assumptions:
            1. searchLib() was called before calling identifyVersions()
            2. The call to searchLib() returned a number > 0

        Args:
            logger (logger): elementals logger instance

        Return Value:
            list of Textual ID(s) of the library's version(s)
        """
        # check for the error string backup case
        if len(self._version_strings) == 1 and self.VERSION_UNKNOWN in self._version_strings:
            return self._version_strings
        # continue as before
        results = set()
        # extract the version from the copyright string
        for work_str in self._version_strings:
            results.add(self.extractVersion(work_str, start_index=work_str.find(self.VERSION_STRING) + len(self.VERSION_STRING)))
        # return the result
        return list(results)


# Register our class
LuaSeeker.register(LuaSeeker.NAME, LuaSeeker)

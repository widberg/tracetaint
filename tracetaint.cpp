#include "tracetaint.hpp"

int pluginHandle;

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct) {
    initStruct->pluginVersion = 1;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, "TraceTaint", _TRUNCATE);
    pluginHandle = initStruct->pluginHandle;
    return true;
}

PLUG_EXPORT bool plugstop() {
    _plugin_logputs("tracetaint plugstop");
    _plugin_unregistercommand(pluginHandle, "tracetaint");
    return true;
}

bool tracetaint_command(int argc, char *argv[]) {
    _plugin_logputs("tracetaint command");
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    _plugin_logputs("tracetaint plugsetup");
    _plugin_registercommand(pluginHandle, "tracetaint", tracetaint_command, false);

}

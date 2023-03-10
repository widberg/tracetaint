#include "pluginsdk/bridgemain.h"
#include <pluginsdk/_plugins.h>
#include <Zydis/Zydis.h>
#include <inttypes.h>
#include <cstdint>
#include <set>
#include <cstdlib>
#include <vcruntime_string.h>

#include "taintengine.hpp"

#define PLUG_EXPORT extern "C" __declspec(dllexport)

int pluginHandle;
int hMenu;

TaintEngine te;

enum
{
	MENU_ENABLED,
	MENU_STOP,
};

static bool traceTaintEnabled = true;
static bool traceTaintStop = false;

static bool updateTaint();

PLUG_EXPORT void CBMENUENTRY(CBTYPE, PLUG_CB_MENUENTRY* info)
{
    _plugin_logputs("tracetaint CBMENUENTRY");
	switch(info->hEntry)
	{
	case MENU_ENABLED:
        {
            traceTaintEnabled = !traceTaintEnabled;
            BridgeSettingSetUint("TraceTaint", "Enabled", traceTaintEnabled);
        }
        break;
	case MENU_STOP:
        {
            traceTaintStop = !traceTaintStop;
            BridgeSettingSetUint("TraceTaint", "Stop", traceTaintStop);
        }
        break;
	}
}

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct) {
    _plugin_logputs("tracetaint pluginit 0");
    initStruct->pluginVersion = 1;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, "TraceTaint", _TRUNCATE);
    pluginHandle = initStruct->pluginHandle;
    _plugin_logputs("tracetaint pluginit 1");

	duint setting = traceTaintEnabled;
	BridgeSettingGetUint("TraceTaint", "Enabled", &setting);
	traceTaintEnabled = !!setting;

	setting = traceTaintStop;
	BridgeSettingGetUint("TraceTaint", "Stop", &setting);
	traceTaintStop = !!setting;
    _plugin_logputs("tracetaint pluginit 2");
    return true;
}

PLUG_EXPORT bool plugstop() {
    _plugin_logputs("tracetaint plugstop");
    _plugin_unregistercommand(pluginHandle, "tracetaint_mem");
    _plugin_unregistercommand(pluginHandle, "tracetaint_reg");
    _plugin_unregistercommand(pluginHandle, "tracetaint_clear");
    _plugin_unregistercommand(pluginHandle, "tracetaint_dump");
    _plugin_unregistercommand(pluginHandle, "tracetaint_enable");
    _plugin_unregistercommand(pluginHandle, "tracetaint_update");
    return true;
}

bool tracetaint_mem(int argc, char *argv[]) {
    _plugin_logputs("tracetaint tracetaint_mem");
    if (argc < 2 || argc > 4) {
        return false;
    }
    duint address = DbgValFromString(argv[1]);
    duint size = 1;
    duint tainted = 1;
    
    if (argc > 2) {
        size = DbgValFromString(argv[2]);
    }
    
    if (argc > 3) {
        tainted = DbgValFromString(argv[3]);
    }

    te.setMemoryTainted(address, size, tainted);

    return true;
}

bool tracetaint_reg(int argc, char *argv[]) {
    _plugin_logputs("tracetaint tracetaint_reg");
    if (argc < 2 || argc > 3) {
        return false;
    }
    duint tainted = 1;
    
    ZydisRegister reg = TaintEngine::registerGetFromString(argv[1]);

    if (reg == ZYDIS_REGISTER_NONE) {
        return false;
    }

    if (argc > 2) {
        tainted = DbgValFromString(argv[2]);
    }

    te.setRegisterTainted(reg, tainted);

    return true;
}

bool tracetaint_clear(int argc, char *argv[]) {
    _plugin_logputs("tracetaint tracetaint_clear");
    te.clear();
    return true;
}

bool tracetaint_dump(int argc, char *argv[]) {
    _plugin_logputs("tracetaint tracetaint_dump");
    _plugin_logputs(te.dump().c_str());
    return true;
}

bool tracetaint_enable(int argc, char *argv[]) {
    _plugin_logputs("tracetaint tracetaint_enable");
    if (argc > 2) {
        return false;
    }
    if (argc > 1) {
        traceTaintEnabled = DbgValFromString(argv[1]);
    } else {
        traceTaintEnabled = !traceTaintEnabled;
		BridgeSettingSetUint("TraceTaint", "Enabled", traceTaintEnabled);
    }
    return true;
}

bool tracetaint_update(int argc, char *argv[]) {
    _plugin_logputs("tracetaint tracetaint_update");
    updateTaint();
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    hMenu = setupStruct->hMenu;
    _plugin_logputs("tracetaint plugsetup 0");
    _plugin_registercommand(pluginHandle, "tracetaint_mem", tracetaint_mem, false);
    _plugin_registercommand(pluginHandle, "tracetaint_reg", tracetaint_reg, false);
    _plugin_registercommand(pluginHandle, "tracetaint_clear", tracetaint_clear, false);
    _plugin_registercommand(pluginHandle, "tracetaint_dump", tracetaint_dump, false);
    _plugin_registercommand(pluginHandle, "tracetaint_enable", tracetaint_enable, false);
    _plugin_registercommand(pluginHandle, "tracetaint_update", tracetaint_update, false);
    
    _plugin_logputs("tracetaint plugsetup 1");
	_plugin_menuaddentry(hMenu, MENU_ENABLED, "Enabled");
	_plugin_menuentrysetchecked(pluginHandle, MENU_ENABLED, traceTaintEnabled);
	_plugin_menuaddentry(hMenu, MENU_STOP, "Stop");
	_plugin_menuentrysetchecked(pluginHandle, MENU_STOP, traceTaintStop);
    _plugin_logputs("tracetaint plugsetup 2");
}

static void getRegisterContext(ZydisRegisterContext *register_context) {
    REGDUMP regdump;
    DbgGetRegDumpEx(&regdump, sizeof(regdump));
    // General Purpose Registers
    // CAX
    register_context->values[ZYDIS_REGISTER_AL] = regdump.regcontext.cax & 0xFF;
    register_context->values[ZYDIS_REGISTER_AH] = (regdump.regcontext.cax & 0xFF00) >> 8;
    register_context->values[ZYDIS_REGISTER_AX] = regdump.regcontext.cax & 0xFFFF;
    register_context->values[ZYDIS_REGISTER_EAX] = regdump.regcontext.cax & 0xFFFFFFFF;
    register_context->values[ZYDIS_REGISTER_RAX] = regdump.regcontext.cax;
    // CCX
    register_context->values[ZYDIS_REGISTER_CL] = regdump.regcontext.ccx & 0xFF;
    register_context->values[ZYDIS_REGISTER_CH] = (regdump.regcontext.ccx & 0xFF00) >> 8;
    register_context->values[ZYDIS_REGISTER_CX] = regdump.regcontext.ccx & 0xFFFF;
    register_context->values[ZYDIS_REGISTER_ECX] = regdump.regcontext.ccx & 0xFFFFFFFF;
    register_context->values[ZYDIS_REGISTER_RCX] = regdump.regcontext.ccx;
    // CDX
    register_context->values[ZYDIS_REGISTER_DL] = regdump.regcontext.cdx & 0xFF;
    register_context->values[ZYDIS_REGISTER_DH] = (regdump.regcontext.cdx & 0xFF00) >> 8;
    register_context->values[ZYDIS_REGISTER_DX] = regdump.regcontext.cdx & 0xFFFF;
    register_context->values[ZYDIS_REGISTER_EDX] = regdump.regcontext.cdx & 0xFFFFFFFF;
    register_context->values[ZYDIS_REGISTER_RDX] = regdump.regcontext.cdx;
    // CBX
    register_context->values[ZYDIS_REGISTER_BL] = regdump.regcontext.cbx & 0xFF;
    register_context->values[ZYDIS_REGISTER_BH] = (regdump.regcontext.cbx & 0xFF00) >> 8;
    register_context->values[ZYDIS_REGISTER_BX] = regdump.regcontext.cbx & 0xFFFF;
    register_context->values[ZYDIS_REGISTER_EBX] = regdump.regcontext.cbx & 0xFFFFFFFF;
    register_context->values[ZYDIS_REGISTER_RBX] = regdump.regcontext.cbx;
    // CSP
    register_context->values[ZYDIS_REGISTER_SPL] = regdump.regcontext.csp & 0xFF;
    register_context->values[ZYDIS_REGISTER_SP] = regdump.regcontext.csp & 0xFFFF;
    register_context->values[ZYDIS_REGISTER_ESP] = regdump.regcontext.csp & 0xFFFFFFFF;
    register_context->values[ZYDIS_REGISTER_RSP] = regdump.regcontext.csp;
    // CBP
    register_context->values[ZYDIS_REGISTER_BPL] = regdump.regcontext.cbp & 0xFF;
    register_context->values[ZYDIS_REGISTER_BP] = regdump.regcontext.cbp & 0xFFFF;
    register_context->values[ZYDIS_REGISTER_EBP] = regdump.regcontext.cbp & 0xFFFFFFFF;
    register_context->values[ZYDIS_REGISTER_RBP] = regdump.regcontext.cbp;
    // CSI
    register_context->values[ZYDIS_REGISTER_SIL] = regdump.regcontext.csi & 0xFF;
    register_context->values[ZYDIS_REGISTER_SI] = regdump.regcontext.csi & 0xFFFF;
    register_context->values[ZYDIS_REGISTER_ESI] = regdump.regcontext.csi & 0xFFFFFFFF;
    register_context->values[ZYDIS_REGISTER_RSI] = regdump.regcontext.csi;
    // CDI
    register_context->values[ZYDIS_REGISTER_DIL] = regdump.regcontext.cdi & 0xFF;
    register_context->values[ZYDIS_REGISTER_DI] = regdump.regcontext.cdi & 0xFFFF;
    register_context->values[ZYDIS_REGISTER_EDI] = regdump.regcontext.cdi & 0xFFFFFFFF;
    register_context->values[ZYDIS_REGISTER_RDI] = regdump.regcontext.cdi;

    // CIP
    register_context->values[ZYDIS_REGISTER_IP] = regdump.regcontext.cip & 0xFFFF;
    register_context->values[ZYDIS_REGISTER_EIP] = regdump.regcontext.cip & 0xFFFFFFFF;

    // EFLAGS
    register_context->values[ZYDIS_REGISTER_EFLAGS] = regdump.regcontext.eflags & 0xFFFFFFFF;

    // Segment Registers
    register_context->values[ZYDIS_REGISTER_ES] = regdump.regcontext.es;
    register_context->values[ZYDIS_REGISTER_CS] = regdump.regcontext.cs;
    register_context->values[ZYDIS_REGISTER_SS] = regdump.regcontext.ss;
    register_context->values[ZYDIS_REGISTER_DS] = regdump.regcontext.ds;
    register_context->values[ZYDIS_REGISTER_FS] = regdump.regcontext.fs;
    register_context->values[ZYDIS_REGISTER_GS] = regdump.regcontext.gs;
}

static bool updateTaint() {
	if(!traceTaintEnabled)
		return false;
    
    ZydisRegisterContext register_context;
    getRegisterContext(&register_context);
    duint cip = (duint)register_context.values[ZYDIS_REGISTER_EIP];

    BASIC_INSTRUCTION_INFO basic_instruction_info;
    DbgDisasmFastAt(cip, &basic_instruction_info);
    unsigned char data[16];
    DbgMemRead(cip, data, basic_instruction_info.size);
    ZydisDisassembledInstruction instruction;
    if (!ZYAN_SUCCESS(ZydisDisassembleIntel( 
        /* machine_mode:    */ ZYDIS_MACHINE_MODE_LEGACY_32, 
        /* runtime_address: */ (ZyanU64)cip, 
        /* buffer:          */ data,
        /* length:          */ basic_instruction_info.size,
        /* instruction:     */ &instruction
    ))) {
        _plugin_logputs("tracetaint zydis failed");
        return false;
    }

    if (te.updateTaint(&instruction, &register_context)) {
        _plugin_logputs("tracetaint taint propagated");
        _plugin_logprintf("%p %s\n", cip, basic_instruction_info.instruction);
        _plugin_logputs(te.dump().c_str());
        return true;
    }
    return false;
}

PLUG_EXPORT void CBINITDEBUG(CBTYPE, PLUG_CB_INITDEBUG* info) {
    _plugin_logputs("tracetaint CBINITDEBUG");
    te.clear();
}

PLUG_EXPORT void CBSTEPPED(CBTYPE, PLUG_CB_STEPPED* info) {
    _plugin_logputs("tracetaint CBSTEPPED");
    updateTaint();
}

PLUG_EXPORT void CBTRACEEXECUTE(CBTYPE, PLUG_CB_TRACEEXECUTE* info) {
    _plugin_logputs("tracetaint CBTRACEEXECUTE");
    info->stop = false;
    if (updateTaint() && traceTaintStop) {
        info->stop = true;
    }
}

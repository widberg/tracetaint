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

TaintEngine te;

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct) {
    initStruct->pluginVersion = 1;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, "TraceTaint", _TRUNCATE);
    pluginHandle = initStruct->pluginHandle;
    return true;
}

PLUG_EXPORT bool plugstop() {
    _plugin_logputs("tracetaint plugstop");
    _plugin_unregistercommand(pluginHandle, "tracetaint_mem");
    _plugin_unregistercommand(pluginHandle, "tracetaint_reg");
    _plugin_unregistercommand(pluginHandle, "tracetaint_clear");
    _plugin_unregistercommand(pluginHandle, "tracetaint_dump");
    return true;
}

bool tracetaint_mem(int argc, char *argv[]) {
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
    te.clear();
    return true;
}

bool tracetaint_dump(int argc, char *argv[]) {
    te.dump();
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    _plugin_logputs("tracetaint plugsetup");
    _plugin_registercommand(pluginHandle, "tracetaint_mem", tracetaint_mem, false);
    _plugin_registercommand(pluginHandle, "tracetaint_reg", tracetaint_reg, false);
    _plugin_registercommand(pluginHandle, "tracetaint_clear", tracetaint_clear, false);
    _plugin_registercommand(pluginHandle, "tracetaint_dump", tracetaint_dump, false);
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

static void updateTaint() {
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
        return;
    }

    if (te.updateTaint(&instruction, &register_context)) {
        _plugin_logputs("tracetaint taint propagated");
        _plugin_logprintf("%p %s\n", cip, basic_instruction_info.instruction);
        te.dump();
    }
}

PLUG_EXPORT void CBSTEPPED(CBTYPE, PLUG_CB_STEPPED* info) {
    updateTaint();
}

PLUG_EXPORT void CBTRACEEXECUTE(CBTYPE, PLUG_CB_TRACEEXECUTE* info) {
    updateTaint();
}

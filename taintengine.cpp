#include "taintengine.hpp"

#include <cstring>
#include <sstream>

void TaintEngine::setOperandTainted(ZydisDisassembledInstruction *instruction, ZydisDecodedOperand *operand, ZydisRegisterContext *register_context, bool tainted) {
    switch (operand->type) {
    case ZYDIS_OPERAND_TYPE_REGISTER:
        setRegisterTainted(operand->reg.value, tainted);
    case ZYDIS_OPERAND_TYPE_MEMORY:
    {
        switch (operand->mem.type) {
        case ZYDIS_MEMOP_TYPE_AGEN:
        case ZYDIS_MEMOP_TYPE_MIB:
            return;
        default:
            break;
        }
        ZyanU64 result_address; 
        ZydisCalcAbsoluteAddressEx(&instruction->info, operand, register_context->values[ZYDIS_REGISTER_EIP], register_context, &result_address);
        setMemoryTainted(result_address, operand->size / 8, tainted);
    }
    default:
        break;
    }
}

bool TaintEngine::isOperandTainted(ZydisDisassembledInstruction *instruction, ZydisDecodedOperand *operand, ZydisRegisterContext *register_context) const {
    switch (operand->type) {
    case ZYDIS_OPERAND_TYPE_REGISTER:
        return isRegisterTainted(operand->reg.value);
    case ZYDIS_OPERAND_TYPE_MEMORY:
    {
        switch (operand->mem.type) {
        case ZYDIS_MEMOP_TYPE_AGEN:
            return isRegisterTainted(operand->mem.base) || isRegisterTainted(operand->mem.index);
        case ZYDIS_MEMOP_TYPE_MIB:
            return isRegisterTainted(operand->mem.base);
        default:
            break;
        }
        ZyanU64 result_address; 
        ZydisCalcAbsoluteAddressEx(&instruction->info, operand, register_context->values[ZYDIS_REGISTER_EIP], register_context, &result_address);
        return isMemoryTainted(result_address);
    }
    default:
        break;
    }
    return false;
}

void TaintEngine::setRegisterTainted(ZydisRegister reg, bool tainted) {
    taintedregisters[registerGetLargestEnclosingOrRegister(reg)] = tainted;
}

bool TaintEngine::isRegisterTainted(ZydisRegister reg) const {
    return taintedregisters[registerGetLargestEnclosingOrRegister(reg)];
}

void TaintEngine::setMemoryTainted(ZyanU64 address, ZyanU64 size, bool tainted) {
    for (int i = 0; i < size; ++i) {
        if (tainted) {
            taintedaddresses.insert(address + i);
        } else {
            taintedaddresses.erase(address + i);
        }
    }
}

bool TaintEngine::isMemoryTainted(ZyanU64 address) const {
    return taintedaddresses.count(address);
}

void TaintEngine::clear() {
    taintedaddresses.clear();
    memset(taintedregisters, 0, sizeof(taintedregisters));
}

std::string TaintEngine::dump() const {
    std::stringstream ss;
    for (auto address : taintedaddresses) {
        ss << std::hex << address << '\n';
    }
    for (int i = 0; i < sizeof(taintedregisters) / sizeof(taintedregisters[0]); ++i) {
        if (taintedregisters[i]) {
            ss << ZydisRegisterGetString((ZydisRegister)i) << '\n';
        }
    }
    return ss.str();
}

bool TaintEngine::updateTaint(ZydisDisassembledInstruction *instruction, ZydisRegisterContext *register_context) {
    switch (instruction->info.mnemonic) {
    case ZYDIS_MNEMONIC_XOR:
        if(instruction->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
               && instruction->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
               && instruction->operands[0].reg.value == instruction->operands[1].reg.value) {
            return false;
        }
        break;
    default:
        break;
    }

    bool tainted = false;
    for (std::size_t i = 0; i < instruction->info.operand_count; ++i) {
        ZydisDecodedOperand operand = instruction->operands[i];
        if ((operand.actions | ZYDIS_OPERAND_ACTION_MASK_READ) != 0 && isOperandTainted(instruction, &operand, register_context)) {
            tainted = true;
            break;
        }
    }
    
    for (std::size_t i = 0; i < instruction->info.operand_count; ++i) {
        ZydisDecodedOperand operand = instruction->operands[i];
        if ((operand.actions | ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0) {
            setOperandTainted(instruction, &operand, register_context, tainted);
        }
    }

    return tainted;
}

ZydisRegister TaintEngine::registerGetLargestEnclosingOrRegister(ZydisRegister reg) {
    ZydisRegister enclosing = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LEGACY_32, reg);
    if (enclosing == ZYDIS_REGISTER_NONE) {
        enclosing = reg;
    }
    return enclosing;
}

ZydisRegister TaintEngine::registerGetFromString(char const *str) {
    ZydisRegister reg = ZYDIS_REGISTER_NONE;

    for (int i = 0; i < ZYDIS_REGISTER_MAX_VALUE; ++i) {
        if (!std::strcmp(ZydisRegisterGetString((ZydisRegister)i), str)) {
            reg = registerGetLargestEnclosingOrRegister((ZydisRegister)i);
            break;
        }
    }

    return reg;
}

#ifndef TAINTENGINE_HPP
#define TAINTENGINE_HPP

#include <set>
#include <string>
#include <Zydis/Zydis.h>

class TaintEngine {
public:
    void setOperandTainted(ZydisDisassembledInstruction *instruction, ZydisDecodedOperand *operand, ZydisRegisterContext *register_context, bool tainted);
    bool isOperandTainted(ZydisDisassembledInstruction *instruction, ZydisDecodedOperand *operand, ZydisRegisterContext *register_context) const;

    void setRegisterTainted(ZydisRegister reg, bool tainted);
    bool isRegisterTainted(ZydisRegister reg) const;

    void setMemoryTainted(ZyanU64 address, ZyanU64 size, bool tainted);
    bool isMemoryTainted(ZyanU64 address) const;

    void clear();
    std::string dump() const;

    bool updateTaint(ZydisDisassembledInstruction *instruction, ZydisRegisterContext *register_context);
    static ZydisRegister registerGetLargestEnclosingOrRegister(ZydisRegister reg);
    static ZydisRegister registerGetFromString(char const *str);
private:
    std::set<ZyanU64> taintedaddresses;
    bool taintedregisters[ZYDIS_REGISTER_MAX_VALUE] = {};
};

#endif // !TAINTENGINE_HPP

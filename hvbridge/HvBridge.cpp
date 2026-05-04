#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// HV_STATUS codes (mirrors Vmx.h — kept local so DLL has no kernel header dep).
#define HV_STATUS_SUCCESS        0x00ULL
#define HV_STATUS_INVALID_CALL   0x01ULL
#define HV_STATUS_NOT_SUPPORTED  0x02ULL
#define HV_STATUS_BAD_ALIGNMENT  0x03ULL

// Valid EPT policy bits exposed to callers.
#define EPT_READ      (1ULL << 0)
#define EPT_WRITE     (1ULL << 1)
#define EPT_EXEC      (1ULL << 2)
#define EPT_EXEC_USER (1ULL << 10)
#define HV_EPT_POLICY_MASK (EPT_READ | EPT_WRITE | EPT_EXEC | EPT_EXEC_USER)

// Maximum 48-bit physical address (i9-14900K limit).
#define MAX_PHYSICAL_ADDRESS ((1ULL << 48) - 1)

// Defined in VmCall.asm.
extern "C" unsigned long long AsmVmCall(unsigned long long Gpa,
                                         unsigned long long Policy);
extern "C" unsigned long long AsmVmCallRaw(unsigned long long Id,
                                            unsigned long long Arg0,
                                            unsigned long long Arg1);

// IssueHypercall — hardcoded to HV_CALL_SET_EPT_POLICY (0x05).
// Validates GPA alignment, bounds, and policy bits before calling the stub.
extern "C" __declspec(dllexport)
unsigned long long IssueHypercall(unsigned long long Gpa,
                                   unsigned long long Policy)
{
    if (Gpa & 0xFFFULL)
        return HV_STATUS_BAD_ALIGNMENT;

    if (Gpa == 0 || Gpa > MAX_PHYSICAL_ADDRESS)
        return HV_STATUS_INVALID_CALL;

    if (Policy & ~HV_EPT_POLICY_MASK)
        return HV_STATUS_INVALID_CALL;

    return AsmVmCall(Gpa, Policy);
}

// IssueHypercallRaw — caller supplies hypercall ID, Arg0 (GPA), and Arg1.
// Validates GPA alignment and bounds; Arg1 semantics are ID-dependent.
// Used by Python for any hypercall other than 0x05 (e.g. WP_REGISTER 0x07,
// GET_PERF_COUNTERS 0x03).
extern "C" __declspec(dllexport)
unsigned long long IssueHypercallRaw(unsigned long long Id,
                                      unsigned long long Arg0,
                                      unsigned long long Arg1)
{
    // For any hypercall that takes a GPA as Arg0, enforce alignment and bounds.
    // Arg0 == 0 is allowed for calls that don't take a GPA (e.g. 0x03).
    if (Arg0 != 0) {
        if (Arg0 & 0xFFFULL)
            return HV_STATUS_BAD_ALIGNMENT;
        if (Arg0 > MAX_PHYSICAL_ADDRESS)
            return HV_STATUS_INVALID_CALL;
    }

    return AsmVmCallRaw(Id, Arg0, Arg1);
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }

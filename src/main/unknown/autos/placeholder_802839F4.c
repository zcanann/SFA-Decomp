#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802839F4.h"

extern void salDeactivateVoice(void *entry);
extern void fn_8027BEBC(void);
extern void fn_8027BFC4(void);
extern u8 *lbl_803DE344;
extern u8 lbl_803CC1E0[];

/*
 * hwSetVolume - large mix-volume setter; computes 4-channel pan from
 * 3-axis float input via fn_8027F2AC, clamps each to s16, and writes
 * back to the voice's pan/volume table. Stubbed pending full decode.
 */
#pragma dont_inline on
void hwSetVolume(int slot, f32 a, f32 b, f32 c, void *aux)
{
    (void)slot;
    (void)a;
    (void)b;
    (void)c;
    (void)aux;
}
#pragma dont_inline reset

/*
 * Disable a voice slot.
 *
 * EN v1.0 Address: 0x80283AB0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80283B0C
 * EN v1.1 Size: 44b
 */
void hwOff(int slot)
{
    salDeactivateVoice(lbl_803DE344 + slot * 0xf4);
}

/*
 * Set the four AUX-mix DSP processing callbacks for a voice slot.
 *
 * EN v1.0 Address: 0x80283AB4
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80283B38
 * EN v1.1 Size: 40b
 */
void hwSetAUXProcessingCallbacks(u8 idx, void *cb0, void *cb1, void *cb2, void *cb3)
{
    u8 *entry = lbl_803CC1E0 + idx * 0xbc;
    *(void **)(entry + 0xac) = cb0;
    *(void **)(entry + 0xb4) = cb1;
    *(void **)(entry + 0xb0) = cb2;
    *(void **)(entry + 0xb8) = cb3;
}

/*
 * Activate the audio "studio" effect chain - thin wrapper.
 *
 * EN v1.1 Address: 0x80283B60
 * EN v1.1 Size: 32b
 */
void hwActivateStudio(void)
{
    fn_8027BEBC();
}

/*
 * Deactivate the audio "studio" effect chain - thin wrapper.
 *
 * EN v1.1 Address: 0x80283B80
 * EN v1.1 Size: 32b
 */
void hwDeactivateStudio(void)
{
    fn_8027BFC4();
}

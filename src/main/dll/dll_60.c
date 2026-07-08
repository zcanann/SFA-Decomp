/*
 * DLL 0x60 (drakor combat camera) - split boundary stub; empty in the retail
 * object. The combat-camera target-offset solver this file previously held was
 * a drift-duplicate of the live, matched copy fn_8010BF08 in
 * dll_0049_cameramodecombat.c (identical blend algorithm over the shared
 * CameraModeCombatState pathBlend fields); it was dead - never called and
 * absent from the empty target dll_60.o - so it has been removed.
 */

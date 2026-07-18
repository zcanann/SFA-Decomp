#ifndef MAIN_DLL_DLL_000B_DLL0B_H_
#define MAIN_DLL_DLL_000B_DLL0B_H_

#include "main/dll/bonespawndata_struct.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/resource.h"
#include "main/texture.h"
#include "main/mm.h"
#include "main/vecmath.h"

s16 dll_0B_func04(ModgfxSpawnContext* st, int z, int c, s16* b, int e, s16* d, int f, void* g);
void dll_0B_func05(void);
void dll_0B_func06(void);
void dll_0B_func07(void* source);
void dll_0B_func08(void* param);
int dll_0B_func09(void* a0, int a1, int a2, u8 a3, void* a4);
void dll_0B_func0A(s16* p);
void dll_0B_func0B(void);
void dll_0B_func0C(void* source, char value);
void dll_0B_func0D(void* source);
void dll_0B_func0E(void);
void dll_0B_func0F(int source, u8 mode, u8 flagByte, int word40, int word3C);
void dll_0B_func10(void);
void dll_0B_func11(int modelOrResource, float posX, float posY, float posZ, s16 param14, int param10);
void dll_0B_func12(void);
void dll_0B_func13(s16 x);
void dll_0B_func14(s16 value);
void dll_0B_func15(void* params);
void dll_0B_func16(void* a, void* b, void* c, void* d, void* e, int f, void* g);
void dll_0B_func17(u32 flags);
s16 dll_0B_func18(void);
void dll_0B_onMapSetup(void);
void dll_0B_release(void);
void dll_0B_initialise(void);

#endif

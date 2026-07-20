#ifndef MAIN_NEWSHADOWS_H_
#define MAIN_NEWSHADOWS_H_

#include "ghidra_import.h"
#include "main/texture.h"

void updateReflectionTextures(void);
void selectReflectionTexture(int id);
void* textureAlloc512(void);
void findSomething(void* needle);


/* extern-cleanup: defining-file public prototypes */
void initFn_8006d020(void);
f32 fn_8006C670(void);
void drawReflectionTexture(void);
void maybeHudFn_8006c91c(void);
void fn_8006CB24(void);
void fn_8006CB50(void);

u32 getReflectionTexture1(void);
void getReflectionTexture2(u32* out);
void getTextureFn_8006c5e4(u32* out);
void fn_8006C5CC(u32* out);
void newshadows_getReflectionScrollOffsets(f32* outScrollX, f32* outScrollY);
u32 getTextureFn_8006c744(void);
void fn_8006C4F8(u32* out);
void fn_8006C504(Texture** out);
void fn_8006C510(Texture** out);
void fn_8006C51C(Texture** out);
void fn_8006C528(Texture** out);
void fn_8006C534(Texture** out);
void fn_8006C540(Texture** out);
void fn_8006C5B8(u32* out);
void fn_8006C678(int id);
void fn_8006C6A4(int id);
void textureFn_8006c4e0(int* tableOut, int* countOut);
void textureFn_8006c75c(int id);

#endif /* MAIN_NEWSHADOWS_H_ */

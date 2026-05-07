#include "ghidra_import.h"
#include "main/dll/dll_43.h"

typedef struct TitleMenuControl {
  void *vtable;
} TitleMenuControl;

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void fn_8011A7E4(int arg);

extern u8 lbl_803DB424;
extern TitleMenuControl *lbl_803DCA4C;
extern TitleMenuControl *lbl_803DCA70;
extern u8 lbl_803DD6C4;
extern u8 lbl_803DD6CC;
extern u8 lbl_803DD6CD;
extern u8 lbl_803DD6CF;

/*
 * --INFO--
 *
 * Function: fn_80119FAC
 * EN v1.0 Address: 0x80119FAC
 * EN v1.0 Size: 304b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_80119FAC(int param_1, int param_2)
{
  if (param_1 == 0) {
    if (lbl_803DB424 != 0) {
      Sfx_PlayFromObject(0, 0x419);
      fn_8011A7E4(0);
    } else {
      Sfx_PlayFromObject(0, 0x100);
      ((void (**)(int, int))lbl_803DCA4C->vtable)[2](0x14, 5);
      lbl_803DD6CF = 0x23;
      lbl_803DD6CC = 1;
    }
  } else {
    lbl_803DD6CD = 1;
    Sfx_PlayFromObject(0, 0x418);
    ((void (**)(int, int))lbl_803DCA4C->vtable)[2](0x14, 1);
    ((void (**)(int))lbl_803DCA70->vtable)[7](0);
    ((void (**)(int))lbl_803DCA70->vtable)[7](1);
    ((void (**)(int))lbl_803DCA70->vtable)[7](2);
    ((void (**)(int))lbl_803DCA70->vtable)[7](3);
    lbl_803DD6CF = 0x23;
    lbl_803DD6C4 = param_2;
  }
}
#pragma peephole reset
#pragma scheduling reset

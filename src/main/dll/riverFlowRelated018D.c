#include "ghidra_import.h"
#include "main/dll/riverFlowRelated018D.h"

extern int GameBit_Get(int eventId);
extern int objCreateLight(int param_1,int param_2);
extern void modelLightStruct_setField50(int handle,int param_2);
extern void modelLightStruct_setColorsA8AC(int handle,int r,int g,int b,int a);
extern void modelLightStruct_setColors100104(int handle,int r,int g,int b,int a);
extern void lightDistAttenFn_8001dc38(int handle,f32 param_2,f32 param_3);
extern void fn_8001DB54(int handle,int param_2);
extern void lightFn_8001db6c(int handle,f32 param_2,int param_3);
extern void fn_8001D714(int handle,f32 param_2);
extern void fn_8001DAB8(int handle,int r,int g,int b,int a);
extern void fn_8001D9E0(int handle,int r,int g,int b,int a);
extern void fn_8001D620(int handle,int param_2,int param_3);
extern void fn_8001DD40(int handle,int param_2);
extern void fn_8001D730(int handle,f32 param_2,int param_3,int r,int g,int b,int a);
extern void dll_DIM_BossGutSpik_update(void);
extern void fn_801BDCF8(void);
extern void fn_801BDD64(void);
extern void fn_801BDDB4(void);
extern void fn_801BDF20(void);

extern undefined4* lbl_803DCA8C;
extern undefined4* lbl_803DCAB8;
extern int lbl_803DDB90;
extern s8 lbl_803DDB94;
extern f32 lbl_803DDB98;
extern f32 lbl_803DDB9C;
extern f32 lbl_803DDBA0;
extern f32 lbl_803DDBA4;
extern void (*lbl_803DDBA8[2])(void);
extern void (*lbl_803DDBB0[2])(void);
extern f32 lbl_803E4C90;
extern f32 lbl_803E4C9C;
extern f32 lbl_803E4CA0;
extern f32 lbl_803E4CCC;

/*
 * --INFO--
 *
 * Function: dimbosstonsil_init
 * EN v1.0 Address: 0x801BEC70
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x801BEE40
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbosstonsil_init(int obj,undefined4 param_2,int isAltVariant)
{
  u8 variant;
  int state;
  
  state = *(int *)(obj + 0xb8);
  variant = 6;
  if (isAltVariant != 0) {
    variant = variant | 1;
  }
  (*(code *)(*lbl_803DCAB8 + 0x58))(lbl_803E4CCC,obj,param_2,state,2,2,0x102,variant);
  *(void (**)(void))(obj + 0xbc) = dll_DIM_BossGutSpik_update;
  (*(code *)(*lbl_803DCA8C + 0x14))(obj,state,0);
  *(s16 *)(state + 0x270) = 0;
  lbl_803DDB94 = (s8)GameBit_Get(0x20c);
  if (lbl_803DDB94 < 3) {
    *(s8 *)(state + 0x354) = 3 - lbl_803DDB94;
  }
  else {
    *(s8 *)(state + 0x354) = 7 - lbl_803DDB94;
  }
  lbl_803DDBA4 = lbl_803E4C90;
  lbl_803DDBA0 = lbl_803E4C90;
  lbl_803DDB98 = lbl_803E4C90;
  lbl_803DDB9C = lbl_803E4C9C;
  lbl_803DDB90 = objCreateLight(0,1);
  if (lbl_803DDB90 != 0) {
    modelLightStruct_setField50(lbl_803DDB90,2);
    modelLightStruct_setColorsA8AC(lbl_803DDB90,0xff,0,0,0x7f);
    modelLightStruct_setColors100104(lbl_803DDB90,0xff,0,0,0x7f);
    lightDistAttenFn_8001dc38(lbl_803DDB90,lbl_803E4C9C,lbl_803E4CA0);
    fn_8001DB54(lbl_803DDB90,1);
    lightFn_8001db6c(lbl_803DDB90,lbl_803E4C90,1);
    fn_8001D714(lbl_803DDB90,lbl_803E4CA0);
    fn_8001DAB8(lbl_803DDB90,0xff,0x7f,0,0x40);
    fn_8001D9E0(lbl_803DDB90,0xff,0x7f,0,0x40);
    fn_8001D620(lbl_803DDB90,2,0x3c);
    fn_8001DD40(lbl_803DDB90,1);
    fn_8001D730(lbl_803DDB90,lbl_803E4CA0,0,0xff,0,0,0x7f);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dimbosstonsil_release
 * EN v1.0 Address: 0x801BEE60
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbosstonsil_release(void)
{
}

#pragma scheduling off
#pragma peephole off
void dimbosstonsil_initialise(void)
{
  lbl_803DDBB0[0] = fn_801BDF20;
  lbl_803DDBB0[1] = fn_801BDDB4;
  lbl_803DDBA8[0] = fn_801BDD64;
  lbl_803DDBA8[1] = fn_801BDCF8;
}
#pragma peephole reset
#pragma scheduling reset

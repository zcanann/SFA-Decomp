#include "ghidra_import.h"
#include "main/dll/mmshrine/torch1C1.h"

extern undefined4 FUN_800067c0();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_80017620();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017710();
extern uint FUN_80017730();
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008111c();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294ccc();

extern undefined4* DAT_803dd6d4;
extern f64 DOUBLE_803e5c58;
extern f32 lbl_803DC074;
extern f32 lbl_803E5C28;
extern f32 lbl_803E5C2C;
extern f32 lbl_803E5C30;
extern f32 lbl_803E5C34;
extern f32 lbl_803E5C40;
extern f32 lbl_803E5C44;
extern f32 lbl_803E5C48;
extern f32 lbl_803E5C4C;
extern f32 lbl_803E5C50;
extern f32 lbl_803E5C60;

/*
 * --INFO--
 *
 * Function: ecsh_shrine_func0B
 * EN v1.0 Address: 0x801C5ED8
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x801C5EE0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ecsh_shrine_func0B(int param_1,int param_2)
{
  ObjHits_EnableObject(param_1);
  *(undefined4 *)(param_1 + 0xf4) = 0;
  *(uint *)(param_1 + 0xf8) =
       CONCAT22(*(undefined2 *)(param_2 + 0x1c),*(undefined2 *)(param_2 + 0x1a));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c5f28
 * EN v1.0 Address: 0x801C5F28
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801C5F44
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c5f28(ushort *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 local_30;
  
  iVar4 = *(int *)(param_1 + 0x26);
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar1 = FUN_80017a98();
  if ((param_1[3] & 0x4000) == 0) {
    *(short *)(iVar3 + 0x28) =
         *(short *)(iVar3 + 0x28) + (short)(int)(lbl_803E5C28 * lbl_803DC074);
    *(short *)(iVar3 + 0x2a) =
         *(short *)(iVar3 + 0x2a) + (short)(int)(lbl_803E5C2C * lbl_803DC074);
    *(short *)(iVar3 + 0x2c) =
         *(short *)(iVar3 + 0x2c) + (short)(int)(lbl_803E5C30 * lbl_803DC074);
    dVar5 = (double)FUN_80293f90();
    *(float *)(param_1 + 8) = lbl_803E5C34 + (float)((double)*(float *)(iVar4 + 0xc) + dVar5);
    dVar5 = (double)FUN_80293f90();
    dVar6 = (double)FUN_80293f90();
    param_1[2] = (ushort)(int)(lbl_803E5C40 * (float)(dVar6 + dVar5));
    dVar5 = (double)FUN_80293f90();
    dVar6 = (double)FUN_80293f90();
    param_1[1] = (ushort)(int)(lbl_803E5C40 * (float)(dVar6 + dVar5));
    FUN_8002fc3c((double)lbl_803E5C44,(double)lbl_803DC074);
    if (iVar1 != 0) {
      uVar2 = FUN_80017730();
      uVar2 = (uVar2 & 0xffff) - (uint)*param_1;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *param_1 = *param_1 +
                 (short)(int)(((float)(local_30 - DOUBLE_803e5c58) * lbl_803DC074) /
                             lbl_803E5C48);
      dVar5 = (double)FUN_80017710((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      if ((double)lbl_803E5C4C < dVar5) {
        *(undefined *)(param_1 + 0x1b) = 0xff;
      }
      else {
        *(char *)(param_1 + 0x1b) =
             (char)(int)(lbl_803E5C50 * (float)(dVar5 / (double)lbl_803E5C4C));
      }
    }
  }
  else {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0xc);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c61f4
 * EN v1.0 Address: 0x801C61F4
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801C6298
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c61f4(undefined4 param_1,undefined4 param_2,int param_3)
{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  
  iVar2 = FUN_8028683c();
  piVar5 = *(int **)(iVar2 + 0xb8);
  iVar3 = FUN_80017a98();
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    cVar1 = *(char *)(param_3 + iVar4 + 0x81);
    if (cVar1 != '\0') {
      switch(cVar1) {
      case '\x03':
        *(undefined *)(piVar5 + 0xc) = 1;
        break;
      case '\a':
        FUN_80294ccc(iVar3,8,1);
        FUN_80017698(0x143,1);
        FUN_80017698(0xba8,1);
        break;
      case '\r':
        (**(code **)(*DAT_803dd6d4 + 0x50))(0x48,100,0,0x50);
        break;
      case '\x0e':
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        if (*piVar5 != 0) {
          FUN_800175cc((double)lbl_803E5C60,*piVar5,'\0');
        }
        break;
      case '\x0f':
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) & 0xbfff;
        if (*piVar5 != 0) {
          FUN_800175cc((double)lbl_803E5C60,*piVar5,'\0');
        }
      }
    }
    *(undefined *)(param_3 + iVar4 + 0x81) = 0;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: ecsh_shrine_getExtraSize
 * EN v1.0 Address: 0x801C5F40
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ecsh_shrine_getExtraSize(void)
{
  return 0x38;
}

/*
 * --INFO--
 *
 * Function: ecsh_shrine_func08
 * EN v1.0 Address: 0x801C5F48
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ecsh_shrine_func08(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: ecsh_shrine_hitDetect
 * EN v1.0 Address: 0x801C60B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ecsh_shrine_hitDetect(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c6358
 * EN v1.0 Address: 0x801C6358
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x801C6504
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c6358(int param_1)
{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  FUN_800067c0((int *)0xd8,0);
  FUN_800067c0((int *)0xd9,0);
  FUN_800067c0((int *)0x8,0);
  FUN_800067c0((int *)0xd,0);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    *puVar2 = 0;
  }
  ObjGroup_RemoveObject(param_1,0xb);
  FUN_80017698(0xefa,0);
  FUN_80017698(0xcbb,1);
  FUN_80017698(0xa7f,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c6404
 * EN v1.0 Address: 0x801C6404
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801C65B0
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c6404(void)
{
  int iVar1;
  char in_r8;
  int *piVar2;
  
  iVar1 = FUN_8028683c();
  piVar2 = *(int **)(iVar1 + 0xb8);
  if (in_r8 == '\0') {
    if (*piVar2 != 0) {
      FUN_800175cc((double)lbl_803E5C60,*piVar2,'\0');
    }
  }
  else {
    if (*piVar2 != 0) {
      FUN_800175cc((double)lbl_803E5C60,*piVar2,'\x01');
    }
    FUN_8003b818(iVar1);
    FUN_8008111c((double)lbl_803E5C60,(double)lbl_803E5C60,iVar1,7,(int *)*piVar2);
  }
  FUN_80286888();
  return;
}

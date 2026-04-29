#include "ghidra_import.h"
#include "main/dll/dll_13F.h"

extern uint FUN_80017690();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 ObjLink_DetachChild();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_80081118();
extern undefined4 FUN_801713ac();
extern undefined8 FUN_801723dc();
extern undefined8 FUN_801726ac();
extern undefined4 FUN_80172974();
extern undefined4 FUN_80172b40();
extern uint countLeadingZeros();

extern undefined4 DAT_803218a8;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803e40d8;
extern undefined4 DAT_803e40dc;
extern f64 DOUBLE_803e40e0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e40e8;
extern f32 FLOAT_803e40ec;
extern f32 FLOAT_803e40f0;
extern f32 FLOAT_803e40f4;
extern f32 FLOAT_803e412c;
extern f32 FLOAT_803e4130;
extern f32 FLOAT_803e4134;
extern f32 FLOAT_803e4138;

/*
 * --INFO--
 *
 * Function: collectible_init
 * EN v1.0 Address: 0x80172F14
 * EN v1.0 Size: 1104b
 * EN v1.1 Address: 0x801730D0
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_init(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                      undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                      short *param_9)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  double dVar5;
  undefined8 uVar6;
  double dVar7;
  uint local_18;
  uint auStack_14 [2];
  
  iVar4 = *(int *)(param_9 + 0x5c);
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
  fVar1 = FLOAT_803e40f4;
  dVar7 = (double)*(float *)(iVar4 + 8);
  dVar5 = (double)FLOAT_803e40f4;
  if (dVar7 == dVar5) {
    if ((int)*(short *)(iVar4 + 0x14) != 0xffffffff) {
      uVar2 = FUN_80017690((int)*(short *)(iVar4 + 0x14));
      uVar2 = countLeadingZeros(uVar2);
      *(char *)(iVar4 + 0x1e) = (char)(uVar2 >> 5);
    }
    if ((*(char *)(iVar4 + 0x1e) == '\0') && (*(char *)(iVar4 + 0xf) == '\0')) {
      if (param_9[0x23] == 0x6a6) {
        in_r7 = 0x14;
        in_r8 = 0;
        in_r9 = 0;
        FUN_800810f4((double)FLOAT_803e40ec,(double)FLOAT_803e40f0,param_9,5,6,1,0x14,0,0);
      }
      dVar7 = (double)*(float *)(iVar4 + 0x44);
      dVar5 = (double)FLOAT_803e40f4;
      if ((dVar7 == dVar5) ||
         (*(float *)(iVar4 + 0x44) = (float)(dVar7 - (double)FLOAT_803dc074),
         dVar5 < (double)*(float *)(iVar4 + 0x44))) {
        while (iVar3 = ObjMsg_Pop((int)param_9,&local_18,auStack_14,(uint *)0x0), iVar3 != 0) {
          if (local_18 == 0x7000b) {
            dVar5 = (double)FUN_801713ac(dVar5,dVar7,param_3,param_4,param_5,param_6,param_7,param_8
                                         ,(uint)param_9);
          }
        }
        if (((param_9[0x23] == 0x319) && (*(short *)(iVar4 + 0x3c) != 0)) &&
           (*(ushort *)(iVar4 + 0x3c) = *(short *)(iVar4 + 0x3c) - (ushort)DAT_803dc070,
           *(short *)(iVar4 + 0x3c) < 1)) {
          *(undefined2 *)(iVar4 + 0x3c) = 0;
          *(byte *)(iVar4 + 0x37) = *(byte *)(iVar4 + 0x37) & 0xfe;
          *(undefined *)(param_9 + 0x1b) = 0xff;
          param_9[0x7a] = 0;
          param_9[0x7b] = 0;
        }
        if (*(int *)(param_9 + 0x7a) == 0) {
          *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
          uVar6 = FUN_801726ac(param_9);
          if (*(char *)(iVar4 + 0x1d) != '\0') {
            uVar6 = FUN_801723dc((int)param_9);
          }
          if (*(char *)(iVar4 + 0x3e) == '\0') {
            FUN_80172b40(uVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8);
          }
          else {
            *(char *)(iVar4 + 0x3e) = *(char *)(iVar4 + 0x3e) + -1;
            if (*(char *)(iVar4 + 0x3e) == '\0') {
              *(undefined2 *)(iVar4 + 0x48) = 0xffff;
              iVar3 = FUN_80017a98();
              ObjMsg_SendToObject(uVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x7000a
                           ,(uint)param_9,iVar4 + 0x48,in_r7,in_r8,in_r9,in_r10);
            }
          }
        }
        else {
          iVar3 = *(int *)(param_9 + 0x2a);
          if (iVar3 != 0) {
            *(ushort *)(iVar3 + 0x60) = *(ushort *)(iVar3 + 0x60) | 0x100;
          }
          ObjHits_DisableObject((int)param_9);
          if (((int)*(short *)(iVar4 + 0x10) != 0xffffffff) &&
             (uVar2 = FUN_80017690((int)*(short *)(iVar4 + 0x10)), uVar2 == 0)) {
            param_9[0x7a] = 0;
            param_9[0x7b] = 0;
          }
        }
      }
      else {
        if ((param_9[3] & 0x2000U) != 0) {
          *(float *)(iVar4 + 8) = FLOAT_803e40e8;
          if (*(int *)(param_9 + 0x32) != 0) {
            *(undefined4 *)(*(int *)(param_9 + 0x32) + 0x30) = 0x1000;
          }
          FUN_80081118((double)FLOAT_803e40ec,param_9,0xff,0x28);
        }
        *(float *)(iVar4 + 0x44) = FLOAT_803e40f4;
      }
    }
  }
  else {
    *(float *)(iVar4 + 8) = (float)(dVar7 - (double)FLOAT_803dc074);
    if ((double)*(float *)(iVar4 + 8) <= dVar5) {
      *(float *)(iVar4 + 8) = fVar1;
      uVar6 = ObjHits_DisableObject((int)param_9);
      if ((param_9[3] & 0x2000U) != 0) {
        FUN_80017ac8(uVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80173364
 * EN v1.0 Address: 0x80173364
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801733C0
 * EN v1.1 Size: 792b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80173364(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80173368
 * EN v1.0 Address: 0x80173368
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801736D8
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80173368(int param_1)
{
  if (*(int *)(param_1 + 0xc4) != 0) {
    ObjLink_DetachChild(*(int *)(param_1 + 0xc4),param_1);
  }
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801733c0
 * EN v1.0 Address: 0x801733C0
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8017372C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801733c0(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: collectible_release
 * EN v1.0 Address: 0x8017321C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80173378
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_release(void)
{
}

/*
 * --INFO--
 *
 * Function: collectible_initialise
 * EN v1.0 Address: 0x80173220
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017337C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int fn_80173224(void) { return 0x288; }

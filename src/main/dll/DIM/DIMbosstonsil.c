#include "ghidra_import.h"
#include "main/dll/DIM/DIMbosstonsil.h"

extern undefined8 FUN_80006728();
extern undefined4 FUN_80006c88();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined8 FUN_80017940();
extern undefined4 FUN_80017a50();
extern int FUN_80017a54();
extern undefined4 FUN_80017a90();
extern undefined4 FUN_80017a98();
extern undefined8 ObjHits_RegisterActiveHitVolumeObject();
extern undefined4 FUN_80080f70();
extern undefined4 FUN_80080f7c();
extern undefined4 FUN_80080f80();
extern undefined4 FUN_801150a4();
extern undefined8 FUN_801150ac();
extern undefined4 FUN_801bbed0();
extern undefined4 FUN_801bcc94();

extern undefined4 DAT_803ad60c;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd738;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5870;
extern f32 FLOAT_803e58dc;
extern f32 FLOAT_803e58e4;
extern f32 FLOAT_803e58e8;
extern f32 FLOAT_803e58ec;

/*
 * --INFO--
 *
 * Function: DIMboss_update
 * EN v1.0 Address: 0x801BD7AC
 * EN v1.0 Size: 1240b
 * EN v1.1 Address: 0x801BDA04
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMboss_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                    undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                    ushort *param_9)
{
  uint uVar1;
  undefined4 uVar2;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  iVar4 = *(int *)(param_9 + 0x5c);
  iVar3 = *(int *)(param_9 + 0x26);
  FUN_80017a98();
  iVar5 = *(int *)(iVar4 + 0x40c);
  if (*(int *)(param_9 + 0x7a) == 0) {
    if ((double)FLOAT_803e5870 < (double)*(float *)(iVar5 + 0xac)) {
      FUN_80006c88((double)*(float *)(iVar5 + 0xac),param_2,param_3,param_4,param_5,param_6,param_7,
                   param_8,0x432);
      *(float *)(iVar5 + 0xac) = *(float *)(iVar5 + 0xac) - FLOAT_803dc074;
      if (*(float *)(iVar5 + 0xac) < FLOAT_803e5870) {
        *(float *)(iVar5 + 0xac) = FLOAT_803e5870;
      }
    }
    uVar6 = ObjHits_RegisterActiveHitVolumeObject(param_9);
    if (*(int *)(param_9 + 0x7c) == 0) {
      *(undefined4 *)(param_9 + 6) = *(undefined4 *)(iVar3 + 8);
      *(undefined4 *)(param_9 + 8) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(param_9 + 10) = *(undefined4 *)(iVar3 + 0x10);
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 0x2e),param_9,0xffffffff);
      param_9[0x7c] = 0;
      param_9[0x7d] = 1;
    }
    else {
      if ((*(ushort *)(iVar4 + 0x400) & 2) != 0) {
        in_r7 = iVar4 + 0x405;
        in_r8 = 0;
        in_r9 = 0;
        in_r10 = 0;
        (**(code **)(*DAT_803dd738 + 0x28))
                  (param_9,iVar4,iVar4 + 0x35c,(int)*(short *)(iVar4 + 0x3f4));
        *(ushort *)(iVar4 + 0x400) = *(ushort *)(iVar4 + 0x400) & 0xfffd;
        *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
        *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 0x80;
        uVar1 = FUN_80017690(0x20c);
        if (uVar1 < 3) {
          *(undefined2 *)(iVar4 + 0x402) = 1;
          *(undefined *)(iVar4 + 0x354) = 3;
          *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
          *(float *)(iVar5 + 0xa4) = FLOAT_803e58dc;
          uVar6 = FUN_80017698(0x9e,1);
        }
        else {
          *(undefined2 *)(iVar4 + 0x402) = 2;
          *(undefined *)(iVar4 + 0x354) = 3;
          *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
          uVar6 = FUN_80017698(0x9e,0);
        }
      }
      if ((*(short *)(iVar4 + 0x402) == 0) || (*(short *)(iVar4 + 0x402) == 3)) {
        if ((*(char *)(iVar5 + 0xb4) != '\0') &&
           (*(char *)(iVar5 + 0xb4) = *(char *)(iVar5 + 0xb4) + -1, *(char *)(iVar5 + 0xb4) == '\0')
           ) {
          FUN_80017a50(param_9,(float *)&DAT_803ad60c,'\0');
          iVar3 = FUN_80017a54((int)param_9);
          uVar6 = FUN_80017940(param_9,iVar3);
        }
        if (*(char *)(iVar5 + 0xb6) < '\0') {
          uVar6 = FUN_80006728(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                               0xdb,0,in_r7,in_r8,in_r9,in_r10);
          FUN_80006728(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0xdc,0,
                       in_r7,in_r8,in_r9,in_r10);
          FUN_80080f80(7,1,0);
          FUN_80080f70((double)FLOAT_803e58e4,(double)FLOAT_803e58e8,(double)FLOAT_803e58ec,7);
          FUN_80080f7c(7,0xa0,0xa0,0xff,0x7f,0x28);
          *(byte *)(iVar5 + 0xb6) = *(byte *)(iVar5 + 0xb6) & 0x7f;
        }
      }
      else {
        if ((*(ushort *)(iVar4 + 0x400) & 4) == 0) {
          uVar2 = FUN_80017a98();
          *(undefined4 *)(iVar4 + 0x2d0) = uVar2;
        }
        else {
          uVar2 = FUN_80017a90();
          *(undefined4 *)(iVar4 + 0x2d0) = uVar2;
        }
        if (*(int *)(param_9 + 100) != 0) {
          *(undefined4 *)(*(int *)(param_9 + 100) + 0x30) = *(undefined4 *)(param_9 + 0x18);
        }
        iVar3 = iVar4;
        iVar5 = iVar4;
        FUN_801bcc94(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0,iVar4,
                     iVar4);
        FUN_801150a4(-0x7fc529c4,*(undefined4 *)(iVar4 + 0x2d0));
        uVar6 = FUN_801150ac();
        FUN_801bbed0(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar4,
                     iVar3,iVar5,in_r7,in_r8,in_r9,in_r10);
      }
    }
  }
  return;
}

extern void fn_801BDAF4(void);

/*
 * --INFO--
 *
 * Function: dimboss_initialise
 * EN v1.0 Address: 0x801BDAD4
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimboss_initialise(void)
{
  fn_801BDAF4();
}

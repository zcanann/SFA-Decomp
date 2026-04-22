#include "ghidra_import.h"
#include "main/dll/dll_18E.h"

extern undefined4 FUN_8001d7e0();
extern undefined4 FUN_8001dab8();
extern undefined4 FUN_8001de4c();
extern uint FUN_80022264();
extern undefined4 FUN_8002bac4();
extern undefined4 FUN_80038524();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80060630();
extern undefined4 FUN_801be750();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de810;
extern undefined4 DAT_803de830;
extern f32 FLOAT_803de824;
extern f32 FLOAT_803e5960;

/*
 * --INFO--
 *
 * Function: FUN_801beeac
 * EN v1.0 Address: 0x801BEEAC
 * EN v1.0 Size: 324b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801beeac(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801beff0
 * EN v1.0 Address: 0x801BEFF0
 * EN v1.0 Size: 56b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801beff0(int param_1)
{
  (**(code **)(*DAT_803dd70c + 0xc))(param_1,*(undefined4 *)(param_1 + 0xb8),&DAT_803de830);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bf028
 * EN v1.0 Address: 0x801BF028
 * EN v1.0 Size: 508b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bf028(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  short sVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  undefined uStack_10;
  undefined local_f;
  undefined local_e;
  undefined local_d [5];
  
  iVar5 = *(int *)(param_9 + 0xb8);
  iVar4 = *(int *)(param_9 + 0x4c);
  if (*(int *)(param_9 + 0xf4) == 0) {
    if (*(int *)(param_9 + 0xf8) == 0) {
      *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(iVar4 + 8);
      *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined4 *)(param_9 + 0x14) = *(undefined4 *)(iVar4 + 0x10);
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar4 + 0x2e),param_9,0xffffffff);
      *(undefined4 *)(param_9 + 0xf8) = 1;
    }
    else {
      if ((*(ushort *)(iVar5 + 0x400) & 2) != 0) {
        FLOAT_803de824 = FLOAT_803e5960;
        (**(code **)(*DAT_803dd738 + 0x28))
                  (param_9,iVar5,iVar5 + 0x35c,(int)*(short *)(iVar5 + 0x3f4),iVar5 + 0x405,0,0,0,1)
        ;
        *(ushort *)(iVar5 + 0x400) = *(ushort *)(iVar5 + 0x400) & 0xfffd;
      }
      iVar4 = (**(code **)(*DAT_803dd738 + 0x30))(param_9,iVar5,1);
      if (iVar4 != 0) {
        uVar6 = extraout_f1;
        uVar2 = FUN_8002bac4();
        *(undefined4 *)(iVar5 + 0x2d0) = uVar2;
        FUN_801be750(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0,iVar5,
                     iVar5);
        if (DAT_803de810 != 0) {
          FUN_8001dab8(DAT_803de810,local_d,&local_e,&local_f,&uStack_10);
          FUN_8001d7e0(DAT_803de810,local_d[0],local_e,local_f,0xc0);
          if ((*(char *)(DAT_803de810 + 0x2f8) != '\0') && (*(char *)(DAT_803de810 + 0x4c) != '\0'))
          {
            sVar1 = (ushort)*(byte *)(DAT_803de810 + 0x2f9) + (short)*(char *)(DAT_803de810 + 0x2fa)
            ;
            if (sVar1 < 0) {
              sVar1 = 0;
              *(undefined *)(DAT_803de810 + 0x2fa) = 0;
            }
            else if (0xc < sVar1) {
              uVar3 = FUN_80022264(0xfffffff4,0xc);
              sVar1 = sVar1 + (short)uVar3;
              if (0xff < sVar1) {
                sVar1 = 0xff;
                *(undefined *)(DAT_803de810 + 0x2fa) = 0;
              }
            }
            *(char *)(DAT_803de810 + 0x2f9) = (char)sVar1;
          }
        }
      }
    }
  }
  return;
}

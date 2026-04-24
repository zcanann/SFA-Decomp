// Function: FUN_8021aeb4
// Entry: 8021aeb4
// Size: 892 bytes

/* WARNING: Removing unreachable block (ram,0x8021b208) */
/* WARNING: Removing unreachable block (ram,0x8021aec4) */

void FUN_8021aeb4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  float local_38 [2];
  longlong local_30;
  
  iVar5 = *(int *)(param_9 + 0x4c);
  local_38[0] = FLOAT_803e768c;
  piVar4 = *(int **)(param_9 + 0xb8);
  if ((*(byte *)((int)piVar4 + 0x31) >> 6 & 1) != 0) {
    param_2 = (double)FLOAT_803e7688;
    param_1 = FUN_8009a010((double)FLOAT_803e7690,param_2,param_9,6,(int *)0x0);
  }
  if ((*(short *)(param_9 + 0x46) == 0x86a) || (*(short *)(param_9 + 0x46) == 0x86b)) {
    uVar1 = FUN_80020078(0x609);
    if (uVar1 != 0) {
      *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) & 0xbfff;
    }
  }
  else if ((*piVar4 == 0) && (uVar1 = FUN_8002e144(), (uVar1 & 0xff) != 0)) {
    puVar2 = FUN_8002becc(0x20,0x477);
    *(undefined *)(puVar2 + 2) = 2;
    *(undefined *)((int)puVar2 + 5) = 1;
    *(byte *)((int)puVar2 + 5) = *(byte *)((int)puVar2 + 5) | *(byte *)(iVar5 + 5) & 0x18;
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
    iVar5 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,
                         in_r9,in_r10);
    *(ushort *)(iVar5 + 6) = *(ushort *)(iVar5 + 6) | 0x4000;
    *(undefined4 *)(iVar5 + 0xf4) = 1;
    *piVar4 = iVar5;
  }
  else {
    if (-1 < *(char *)((int)piVar4 + 0x31)) {
      uVar1 = FUN_80020078(0x609);
      if (uVar1 != 0) {
        FUN_80035ff8(param_9);
        *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
        *(byte *)((int)piVar4 + 0x31) = *(byte *)((int)piVar4 + 0x31) & 0x7f | 0x80;
        iVar5 = FUN_80036f50(10,param_9,local_38);
        if (iVar5 == 0) {
          return;
        }
        if (*(short *)(iVar5 + 0x46) != 0x419) {
          return;
        }
        *(undefined4 *)(iVar5 + 0xf4) = 0;
        piVar4[1] = 0;
        return;
      }
      dVar6 = FUN_80021434((double)(FLOAT_803dc078 *
                                    (*(float *)(param_9 + 0xc) - *(float *)(param_9 + 0x80)) *
                                    FLOAT_803e7694 - (float)piVar4[9]),(double)FLOAT_803e7698,
                           (double)FLOAT_803dc074);
      dVar7 = (double)(FLOAT_803e769c * FLOAT_803dc074);
      if ((dVar7 <= dVar6) && (dVar7 = dVar6, (double)(FLOAT_803e76a0 * FLOAT_803dc074) < dVar6)) {
        dVar7 = (double)(FLOAT_803e76a0 * FLOAT_803dc074);
      }
      piVar4[9] = (int)(float)((double)(float)piVar4[9] + dVar7);
      uVar1 = 0;
      dVar7 = (double)FLOAT_803e76a4;
      do {
        iVar3 = FUN_800396d0(param_9,uVar1);
        if (iVar3 != 0) {
          local_30 = (longlong)(int)((double)(float)piVar4[9] / dVar7);
          *(short *)(iVar3 + 4) = (short)(int)((double)(float)piVar4[9] / dVar7);
        }
        uVar1 = uVar1 + 1;
      } while ((int)uVar1 < 9);
      if (*piVar4 != 0) {
        local_30 = (longlong)(int)(float)piVar4[9];
        *(short *)(*piVar4 + 4) = (short)(int)(float)piVar4[9];
        iVar3 = FUN_80036f50(10,param_9,local_38);
        if ((iVar3 != 0) && (*(short *)(iVar3 + 0x46) == 0x419)) {
          *(undefined4 *)(iVar3 + 0xf4) = 1;
          piVar4[1] = iVar3;
          *(undefined2 *)(iVar3 + 4) = *(undefined2 *)(*piVar4 + 4);
          *(undefined4 *)(*piVar4 + 0xf4) = 1;
        }
        if ((piVar4[1] != 0) && ((*(ushort *)(piVar4[1] + 0xb0) & 0x40) != 0)) {
          piVar4[1] = 0;
        }
      }
    }
    if (-1 < *(char *)((int)piVar4 + 0x31)) {
      uVar1 = FUN_80020078(0xc67);
      if (uVar1 == 0) {
        FUN_800201ac(0xea4,0);
      }
      else if ((*(float *)(param_9 + 0xc) < FLOAT_803e76a8) ||
              (FLOAT_803e76ac < *(float *)(param_9 + 0xc))) {
        FUN_800201ac(0xea4,1);
      }
      else {
        FUN_800201ac((int)*(short *)(iVar5 + 0x1e),1);
      }
    }
  }
  return;
}


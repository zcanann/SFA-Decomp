// Function: FUN_801730d0
// Entry: 801730d0
// Size: 752 bytes

void FUN_801730d0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
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
      uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x14));
      uVar2 = countLeadingZeros(uVar2);
      *(char *)(iVar4 + 0x1e) = (char)(uVar2 >> 5);
    }
    if ((*(char *)(iVar4 + 0x1e) == '\0') && (*(char *)(iVar4 + 0xf) == '\0')) {
      if (param_9[0x23] == 0x6a6) {
        in_r7 = 0x14;
        in_r8 = 0;
        in_r9 = 0;
        FUN_80097568((double)FLOAT_803e40ec,(double)FLOAT_803e40f0,param_9,5,6,1,0x14,0,0);
      }
      dVar7 = (double)*(float *)(iVar4 + 0x44);
      dVar5 = (double)FLOAT_803e40f4;
      if ((dVar7 == dVar5) ||
         (*(float *)(iVar4 + 0x44) = (float)(dVar7 - (double)FLOAT_803dc074),
         dVar5 < (double)*(float *)(iVar4 + 0x44))) {
        while (iVar3 = FUN_800375e4((int)param_9,&local_18,auStack_14,(uint *)0x0), iVar3 != 0) {
          if (local_18 == 0x7000b) {
            dVar5 = (double)FUN_80172308(dVar5,dVar7,param_3,param_4,param_5,param_6,param_7,param_8
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
          uVar6 = FUN_80172888(param_9);
          if (*(char *)(iVar4 + 0x1d) != '\0') {
            uVar6 = FUN_801725f0((int)param_9);
          }
          if (*(char *)(iVar4 + 0x3e) == '\0') {
            FUN_80172cd0(uVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8);
          }
          else {
            *(char *)(iVar4 + 0x3e) = *(char *)(iVar4 + 0x3e) + -1;
            if (*(char *)(iVar4 + 0x3e) == '\0') {
              *(undefined2 *)(iVar4 + 0x48) = 0xffff;
              iVar3 = FUN_8002bac4();
              FUN_800379bc(uVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x7000a
                           ,(uint)param_9,iVar4 + 0x48,in_r7,in_r8,in_r9,in_r10);
            }
          }
        }
        else {
          iVar3 = *(int *)(param_9 + 0x2a);
          if (iVar3 != 0) {
            *(ushort *)(iVar3 + 0x60) = *(ushort *)(iVar3 + 0x60) | 0x100;
          }
          FUN_80035ff8((int)param_9);
          if (((int)*(short *)(iVar4 + 0x10) != 0xffffffff) &&
             (uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x10)), uVar2 == 0)) {
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
          FUN_80099c40((double)FLOAT_803e40ec,param_9,0xff,0x28);
        }
        *(float *)(iVar4 + 0x44) = FLOAT_803e40f4;
      }
    }
  }
  else {
    *(float *)(iVar4 + 8) = (float)(dVar7 - (double)FLOAT_803dc074);
    if ((double)*(float *)(iVar4 + 8) <= dVar5) {
      *(float *)(iVar4 + 8) = fVar1;
      uVar6 = FUN_80035ff8((int)param_9);
      if ((param_9[3] & 0x2000U) != 0) {
        FUN_8002cc9c(uVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      }
    }
  }
  return;
}


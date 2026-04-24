// Function: FUN_80172c24
// Entry: 80172c24
// Size: 752 bytes

void FUN_80172c24(int param_1)

{
  float fVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int local_18;
  undefined auStack20 [8];
  
  iVar5 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  fVar1 = FLOAT_803e345c;
  if (*(float *)(iVar5 + 8) == FLOAT_803e345c) {
    if (*(short *)(iVar5 + 0x14) != -1) {
      uVar3 = FUN_8001ffb4();
      uVar2 = countLeadingZeros(uVar3);
      *(char *)(iVar5 + 0x1e) = (char)(uVar2 >> 5);
    }
    if ((*(char *)(iVar5 + 0x1e) == '\0') && (*(char *)(iVar5 + 0xf) == '\0')) {
      if (*(short *)(param_1 + 0x46) == 0x6a6) {
        FUN_800972dc((double)FLOAT_803e3454,(double)FLOAT_803e3458,param_1,5,6,1,0x14,0,0);
      }
      fVar1 = FLOAT_803e345c;
      if ((*(float *)(iVar5 + 0x44) == FLOAT_803e345c) ||
         (*(float *)(iVar5 + 0x44) = *(float *)(iVar5 + 0x44) - FLOAT_803db414,
         fVar1 < *(float *)(iVar5 + 0x44))) {
        while (iVar4 = FUN_800374ec(param_1,&local_18,auStack20,0), iVar4 != 0) {
          if (local_18 == 0x7000b) {
            FUN_80171e5c(param_1);
          }
        }
        if (((*(short *)(param_1 + 0x46) == 0x319) && (*(short *)(iVar5 + 0x3c) != 0)) &&
           (*(ushort *)(iVar5 + 0x3c) = *(short *)(iVar5 + 0x3c) - (ushort)DAT_803db410,
           *(short *)(iVar5 + 0x3c) < 1)) {
          *(undefined2 *)(iVar5 + 0x3c) = 0;
          *(byte *)(iVar5 + 0x37) = *(byte *)(iVar5 + 0x37) & 0xfe;
          *(undefined *)(param_1 + 0x36) = 0xff;
          *(undefined4 *)(param_1 + 0xf4) = 0;
        }
        if (*(int *)(param_1 + 0xf4) == 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          FUN_801723dc(param_1);
          if (*(char *)(iVar5 + 0x1d) != '\0') {
            FUN_80172144(param_1);
          }
          if (*(char *)(iVar5 + 0x3e) == '\0') {
            FUN_80172824(param_1,iVar5);
          }
          else {
            *(char *)(iVar5 + 0x3e) = *(char *)(iVar5 + 0x3e) + -1;
            if (*(char *)(iVar5 + 0x3e) == '\0') {
              *(undefined2 *)(iVar5 + 0x48) = 0xffff;
              uVar3 = FUN_8002b9ec();
              FUN_800378c4(uVar3,0x7000a,param_1,iVar5 + 0x48);
            }
          }
        }
        else {
          iVar4 = *(int *)(param_1 + 0x54);
          if (iVar4 != 0) {
            *(ushort *)(iVar4 + 0x60) = *(ushort *)(iVar4 + 0x60) | 0x100;
          }
          FUN_80035f00(param_1);
          if ((*(short *)(iVar5 + 0x10) != -1) && (iVar5 = FUN_8001ffb4(), iVar5 == 0)) {
            *(undefined4 *)(param_1 + 0xf4) = 0;
          }
        }
      }
      else {
        if ((*(ushort *)(param_1 + 6) & 0x2000) != 0) {
          *(float *)(iVar5 + 8) = FLOAT_803e3450;
          if (*(int *)(param_1 + 100) != 0) {
            *(undefined4 *)(*(int *)(param_1 + 100) + 0x30) = 0x1000;
          }
          FUN_800999b4((double)FLOAT_803e3454,param_1,0xff,0x28);
        }
        *(float *)(iVar5 + 0x44) = FLOAT_803e345c;
      }
    }
  }
  else {
    *(float *)(iVar5 + 8) = *(float *)(iVar5 + 8) - FLOAT_803db414;
    if (*(float *)(iVar5 + 8) <= fVar1) {
      *(float *)(iVar5 + 8) = fVar1;
      FUN_80035f00();
      if ((*(ushort *)(param_1 + 6) & 0x2000) != 0) {
        FUN_8002cbc4(param_1);
      }
    }
  }
  return;
}


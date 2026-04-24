// Function: FUN_8019009c
// Entry: 8019009c
// Size: 580 bytes

void FUN_8019009c(short *param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  iVar1 = FUN_8002b9ec();
  *param_1 = *param_1 + *(short *)(iVar4 + 0x11c);
  param_1[2] = param_1[2] + *(short *)(iVar4 + 0x118);
  param_1[1] = param_1[1] + *(short *)(iVar4 + 0x11a);
  if ((*(byte *)(iVar4 + 0x120) & 1) == 0) {
    *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803db414 + *(float *)(param_1 + 6);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803db414 + *(float *)(param_1 + 8);
    *(float *)(param_1 + 10) =
         *(float *)(param_1 + 0x16) * FLOAT_803db414 + *(float *)(param_1 + 10);
    if (((*(byte *)(iVar4 + 0x120) & 2) != 0) && (FLOAT_803e3e78 < *(float *)(param_1 + 0x14))) {
      *(float *)(param_1 + 0x14) = FLOAT_803e3e7c * FLOAT_803db414 + *(float *)(param_1 + 0x14);
    }
  }
  else {
    iVar2 = FUN_80010320((double)*(float *)(iVar4 + 0x10c),iVar4);
    if ((iVar2 != 0) || (*(int *)(iVar4 + 0x10) != 0)) {
      (**(code **)(*DAT_803dca9c + 0x90))(iVar4);
    }
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar4 + 0x68);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0x6c);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar4 + 0x70);
  }
  if ((iVar1 != 0) && ((*(short *)(iVar4 + 0x116) == -1 || (iVar1 = FUN_8001ffb4(), iVar1 != 0)))) {
    if ((*(char *)(iVar4 + 0x11e) == '\0') ||
       (*(ushort *)(iVar4 + 0x110) = *(short *)(iVar4 + 0x110) - (ushort)DAT_803db410,
       0 < *(short *)(iVar4 + 0x110))) {
      if (*(char *)(iVar4 + 0x11f) == '\0') {
        if ((iVar4 == 0) || ((int)*(short *)(iVar4 + 0x112) != DAT_803ac7be - 1)) {
          uVar3 = FUN_80023cc8(0x28,0x12,0);
          *(undefined4 *)(iVar4 + 0x108) = uVar3;
          FUN_8001f71c(*(undefined4 *)(iVar4 + 0x108),0xc,*(short *)(iVar4 + 0x112) * 0x28,0x28);
          if (*(int *)(iVar4 + 0x108) != 0) {
            FUN_8018ff48(*(int *)(iVar4 + 0x108),&DAT_803ac7b0);
          }
        }
        else {
          uVar3 = FUN_80023cc8(0x28,0x12,0);
          *(undefined4 *)(iVar4 + 0x108) = uVar3;
          if (*(int *)(iVar4 + 0x108) != 0) {
            FUN_8018ff48(&DAT_803ac7b0);
          }
        }
        *(undefined *)(iVar4 + 0x11f) = 1;
      }
    }
    else {
      FUN_8002cbc4(param_1);
    }
  }
  return;
}


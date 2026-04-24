// Function: FUN_801afc90
// Entry: 801afc90
// Size: 876 bytes

void FUN_801afc90(short *param_1)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  
  fVar2 = FLOAT_803db414;
  bVar1 = DAT_803db410;
  if (param_1[0x23] == 0x1fa) {
    *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803db414 + *(float *)(param_1 + 6);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803db414 + *(float *)(param_1 + 8);
    *(float *)(param_1 + 10) =
         *(float *)(param_1 + 0x16) * FLOAT_803db414 + *(float *)(param_1 + 10);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x1f5,0,1,0xffffffff,0);
    *param_1 = *param_1 + (ushort)DAT_803db410 * 0x374;
    param_1[1] = param_1[1] + (ushort)DAT_803db410 * 300;
    *(float *)(param_1 + 0x14) = -(FLOAT_803e47d0 * FLOAT_803db414 - *(float *)(param_1 + 0x14));
    *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803db410;
    if (*(int *)(param_1 + 0x7a) < 0) {
      FUN_8002cbc4(param_1);
    }
  }
  else {
    iVar4 = *(int *)(param_1 + 0x5c);
    if ((*(byte *)(iVar4 + 0x10) & 0x10) == 0) {
      if (*(char *)(iVar4 + 0x11) != '\0') {
        *(char *)(iVar4 + 0x11) = *(char *)(iVar4 + 0x11) + -1;
      }
      *param_1 = *param_1 + (ushort)bVar1 * 0x40;
      param_1[1] = param_1[1] + (ushort)bVar1 * -0x200;
      *(float *)(param_1 + 0x14) = FLOAT_803e47f4 * fVar2 + *(float *)(param_1 + 0x14);
      FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * fVar2),
                   (double)(*(float *)(param_1 + 0x14) * fVar2),
                   (double)(*(float *)(param_1 + 0x16) * fVar2),param_1);
      if (FLOAT_803e47f8 <= *(float *)(param_1 + 0x14)) {
        *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) & 0xdf;
      }
      else if ((*(byte *)(iVar4 + 0x10) & 0x20) == 0) {
        FUN_8000bb18(param_1,0x3dd);
        *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 0x20;
      }
      iVar3 = *(int *)(param_1 + 0x2a);
      if (iVar3 != 0) {
        *(undefined *)(iVar3 + 0x6e) = 0xb;
        *(undefined *)(iVar3 + 0x6f) = 1;
        *(undefined4 *)(iVar3 + 0x48) = 0x10;
        *(undefined4 *)(iVar3 + 0x4c) = 0x10;
        if (*(int *)(iVar3 + 0x50) != 0) {
          if (*(char *)(iVar4 + 0x11) == '\0') {
            *(undefined *)(iVar4 + 0x11) = 10;
            FUN_8009ab70((double)FLOAT_803e47fc,param_1,1,1,0,0,0,0,0);
          }
          else {
            FUN_8009ab70((double)FLOAT_803e47fc,param_1,0,1,0,0,0,0,0);
          }
          *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 0x10;
          param_1[3] = param_1[3] | 0x4000;
        }
        if ((*(byte *)(iVar3 + 0xad) & 1) != 0) {
          FUN_8009ab70((double)FLOAT_803e47fc,param_1,1,1,0,0,0,0,0);
          *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 0x10;
          param_1[3] = param_1[3] | 0x4000;
          return;
        }
      }
      if (*(float *)(param_1 + 8) < *(float *)(iVar4 + 8)) {
        *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 0x10;
      }
      if ((*(byte *)(iVar4 + 0x10) & 8) == 0) {
        *(byte *)(iVar4 + 0x10) = *(byte *)(iVar4 + 0x10) | 8;
      }
      if ((*(int *)(iVar4 + 4) != 0) && (iVar3 = FUN_8001db64(), iVar3 != 0)) {
        FUN_8001d6b0(*(undefined4 *)(iVar4 + 4));
      }
    }
    else {
      FUN_80035f00();
    }
  }
  return;
}


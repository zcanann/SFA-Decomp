// Function: FUN_8021f378
// Entry: 8021f378
// Size: 684 bytes

void FUN_8021f378(uint param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  
  puVar4 = *(uint **)(param_1 + 0xb8);
  *(undefined2 *)((int)puVar4 + 0xc16) = 5;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  uVar2 = countLeadingZeros(*(byte *)((int)puVar4 + 0xc49) >> 3 & 1);
  *(char *)((int)puVar4 + 0x25f) = (char)(uVar2 >> 5);
  *(undefined *)(puVar4 + 0xd5) = 0;
  *puVar4 = *puVar4 & 0xffff7fff;
  fVar1 = FLOAT_803e7740;
  if ((*(ushort *)(puVar4 + 0x310) & 0x40) == 0) {
    puVar4[0xa4] = (uint)FLOAT_803e7740;
    puVar4[0xa3] = (uint)fVar1;
  }
  else {
    iVar3 = FUN_802229a8((double)(FLOAT_803dcf8c * (float)puVar4[0x30a] * FLOAT_803dc074),
                         (double)FLOAT_803e77dc,(double)(FLOAT_803e7774 * FLOAT_803dc074),param_1,
                         (float *)(puVar4 + 0x284),'\0');
    if (iVar3 != 0) {
      if (iVar3 == -1) {
        *(ushort *)(puVar4 + 0x310) = *(ushort *)(puVar4 + 0x310) & 0xfebf;
        *(byte *)((int)puVar4 + 0x9fd) = *(byte *)((int)puVar4 + 0x9fd) & 0xfd;
      }
      else {
        FUN_8021e450(param_1,(char)iVar3);
      }
    }
  }
  puVar4[199] = 0;
  puVar4[0xc6] = 0;
  *(undefined2 *)(puVar4 + 0xcc) = 0;
  *puVar4 = *puVar4 & 0xffbfffff;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e7768),
             (double)FLOAT_803dc074,param_1,puVar4,&DAT_803adea8,&DAT_803de9f8);
  FUN_8021ec08(param_1,(int)puVar4,(int)puVar4);
  FUN_8003b408(param_1,(int)(puVar4 + 0xe3));
  FUN_80039030(param_1,(char *)(puVar4 + 0xef));
  FUN_80115330();
  iVar3 = FUN_8003811c(param_1);
  if (iVar3 != 0) {
    FUN_80014b68(0,0x100);
    iVar3 = (int)*(char *)((int)puVar4 + 0xc4b);
    if (iVar3 != -1) {
      if (iVar3 < 10) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(iVar3,param_1,0xffffffff);
      }
      else {
        FUN_800201ac((int)*(short *)((int)&FLOAT_803dcf68 + iVar3 * 2),1);
      }
    }
  }
  uVar2 = FUN_80022264(0,100);
  if (uVar2 == 0) {
    uVar2 = FUN_80022264(0,2);
    FUN_800393e8(param_1,puVar4 + 0xef,(ushort *)(uVar2 * 6 + -0x7fcd48f8),0);
  }
  if ((*(byte *)((int)puVar4 + 0xc49) & 1) != 0) {
    (**(code **)(*DAT_803dd6e8 + 0x5c))((int)*(short *)(puVar4 + 0x306));
    puVar4[0x30e] = (uint)((float)puVar4[0x30e] + FLOAT_803dc074);
    if (FLOAT_803e77e0 < (float)puVar4[0x30e]) {
      puVar4[0x30e] = (uint)((float)puVar4[0x30e] - FLOAT_803e77e0);
      FUN_8000bb38(param_1,0x47f);
    }
  }
  return;
}


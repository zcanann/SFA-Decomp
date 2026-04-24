// Function: FUN_8021ed28
// Entry: 8021ed28
// Size: 684 bytes

void FUN_8021ed28(int param_1)

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
  fVar1 = FLOAT_803e6aa8;
  if ((*(ushort *)(puVar4 + 0x310) & 0x40) == 0) {
    puVar4[0xa4] = (uint)FLOAT_803e6aa8;
    puVar4[0xa3] = (uint)fVar1;
  }
  else {
    uVar2 = FUN_80222358((double)(FLOAT_803dc324 * (float)puVar4[0x30a] * FLOAT_803db414),
                         (double)FLOAT_803e6b44,(double)(FLOAT_803e6adc * FLOAT_803db414),param_1,
                         puVar4 + 0x284,0);
    if (uVar2 != 0) {
      if (uVar2 == 0xffffffff) {
        *(ushort *)(puVar4 + 0x310) = *(ushort *)(puVar4 + 0x310) & 0xfebf;
        *(byte *)((int)puVar4 + 0x9fd) = *(byte *)((int)puVar4 + 0x9fd) & 0xfd;
      }
      else {
        FUN_8021dda8(param_1,uVar2 & 0xff);
      }
    }
  }
  puVar4[199] = 0;
  puVar4[0xc6] = 0;
  *(undefined2 *)(puVar4 + 0xcc) = 0;
  *puVar4 = *puVar4 & 0xffbfffff;
  (**(code **)(*DAT_803dca8c + 8))
            ((double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) - DOUBLE_803e6ad0),
             (double)FLOAT_803db414,param_1,puVar4,&DAT_803ad248,&DAT_803ddd78);
  FUN_8021e5c4(param_1,puVar4,puVar4);
  FUN_8003b310(param_1,puVar4 + 0xe3);
  FUN_80038f38(param_1,puVar4 + 0xef);
  FUN_80115094(param_1,puVar4 + 0xfb);
  iVar3 = FUN_80038024(param_1);
  if (iVar3 != 0) {
    FUN_80014b3c(0,0x100);
    iVar3 = (int)*(char *)((int)puVar4 + 0xc4b);
    if (iVar3 != -1) {
      if (iVar3 < 10) {
        (**(code **)(*DAT_803dca54 + 0x48))(iVar3,param_1,0xffffffff);
      }
      else {
        FUN_800200e8((int)*(short *)((int)&FLOAT_803dc300 + iVar3 * 2),1);
      }
    }
  }
  iVar3 = FUN_800221a0(0,100);
  if (iVar3 == 0) {
    iVar3 = FUN_800221a0(0,2);
    FUN_800392f0(param_1,puVar4 + 0xef,iVar3 * 6 + -0x7fcd5550,0);
  }
  if ((*(byte *)((int)puVar4 + 0xc49) & 1) != 0) {
    (**(code **)(*DAT_803dca68 + 0x5c))((int)*(short *)(puVar4 + 0x306));
    puVar4[0x30e] = (uint)((float)puVar4[0x30e] + FLOAT_803db414);
    if (FLOAT_803e6b48 < (float)puVar4[0x30e]) {
      puVar4[0x30e] = (uint)((float)puVar4[0x30e] - FLOAT_803e6b48);
      FUN_8000bb18(param_1,0x47f);
    }
  }
  return;
}


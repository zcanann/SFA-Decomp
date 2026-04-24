// Function: FUN_8024cbdc
// Entry: 8024cbdc
// Size: 1144 bytes

void FUN_8024cbdc(void)

{
  short *psVar1;
  ushort uVar2;
  undefined2 *puVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  short sVar8;
  int iVar7;
  short sVar9;
  uint uVar10;
  
  DAT_803debf8 = 1;
  uVar2 = DAT_cc002002;
  if ((uVar2 & 1) == 0) {
    FUN_8024c9e4(0);
  }
  DAT_803debe0 = 0;
  DAT_803dec0c = 0;
  DAT_803dec08 = 0;
  DAT_803dec1c = 0;
  DAT_803dec18 = 0;
  DAT_803dec00 = 0;
  DAT_803dec10 = 0;
  DAT_803debe4 = 0;
  DAT_cc00204e = DAT_8032eb78 | DAT_8032eb7a << 10;
  DAT_cc00204c = (ushort)((int)(uint)DAT_8032eb7a >> 6) | DAT_8032eb7c << 4;
  DAT_cc002052 = DAT_8032eb7e | DAT_8032eb80 << 10;
  DAT_cc002050 = (ushort)((int)(uint)DAT_8032eb80 >> 6) | DAT_8032eb82 << 4;
  DAT_cc002056 = DAT_8032eb84 | DAT_8032eb86 << 10;
  DAT_cc002054 = (ushort)((int)(uint)DAT_8032eb86 >> 6) | DAT_8032eb88 << 4;
  DAT_cc00205a = DAT_8032eb8a | DAT_8032eb8c << 8;
  DAT_cc002058 = DAT_8032eb8e | DAT_8032eb90 << 8;
  DAT_cc00205e = DAT_8032eb92 | DAT_8032eb94 << 8;
  DAT_cc00205c = DAT_8032eb96 | DAT_8032eb98 << 8;
  DAT_cc002062 = DAT_8032eb9a | DAT_8032eb9c << 8;
  DAT_cc002060 = DAT_8032eb9e | DAT_8032eba0 << 8;
  DAT_cc002066 = DAT_8032eba2 | DAT_8032eba4 << 8;
  DAT_cc002064 = DAT_8032eba6 | DAT_8032eba8 << 8;
  DAT_cc002070 = 0x280;
  puVar3 = FUN_80245880();
  DAT_803debfe = 0;
  DAT_803debfc = (short)*(char *)(puVar3 + 8);
  FUN_80245c40(0);
  uVar2 = DAT_cc002002;
  DAT_803aeddc = uVar2 >> 2 & 1;
  DAT_803aede0 = uVar2 >> 8 & 3;
  uVar10 = DAT_803aede0;
  if (DAT_803aede0 == 3) {
    uVar10 = 0;
  }
  DAT_803aee0c = FUN_8024c954(uVar10 * 4 + DAT_803aeddc);
  DAT_803dec24 = DAT_803aede0;
  DAT_803aedbc = 0x280;
  psVar1 = (short *)(DAT_803aee0c + 2);
  DAT_803aedbe = *psVar1 * 2;
  DAT_803aedb8 = 0x28;
  DAT_803aedba = 0;
  DAT_803aedc0 = 0x50;
  iVar4 = DAT_803debfc + 0x28;
  if (iVar4 < 0x51) {
    if (iVar4 < 0) {
      iVar4 = 0;
    }
    DAT_803aedc0 = (undefined2)iVar4;
  }
  if (DAT_803aedd8 == 0) {
    iVar4 = 2;
  }
  else {
    iVar4 = 1;
  }
  iVar5 = (int)DAT_803debfe;
  DAT_803aedc2 = 0;
  if (0 < iVar5) {
    DAT_803aedc2 = DAT_803debfe;
  }
  iVar6 = (int)*psVar1;
  if (DAT_803aedbe + iVar5 + iVar6 * -2 < 1) {
    sVar9 = 0;
  }
  else {
    sVar9 = (short)(DAT_803aedbe + iVar5) + *psVar1 * -2;
  }
  sVar8 = DAT_803debfe;
  if (-1 < iVar5) {
    sVar8 = 0;
  }
  DAT_803aedc4 = (DAT_803aedbe + sVar8) - sVar9;
  iVar7 = iVar5;
  if (-1 < iVar5) {
    iVar7 = 0;
  }
  DAT_803aedc6 = DAT_803aedd0 - (short)(iVar7 / iVar4);
  if (DAT_803aedbe + iVar5 + iVar6 * -2 < 1) {
    iVar6 = 0;
  }
  else {
    iVar6 = DAT_803aedbe + iVar5 + iVar6 * -2;
  }
  if (-1 < iVar5) {
    iVar5 = 0;
  }
  DAT_803aedc8 = (DAT_803aedd4 + (short)(iVar5 / iVar4)) - (short)(iVar6 / iVar4);
  DAT_803aedca = 0x280;
  DAT_803aedcc = *psVar1 << 1;
  DAT_803aedce = 0;
  DAT_803aedd0 = 0;
  DAT_803aedd2 = 0x280;
  DAT_803aedd4 = *psVar1 << 1;
  DAT_803aedd8 = 0;
  DAT_803aede4 = 0x28;
  DAT_803aede5 = 0x28;
  DAT_803aede6 = 0x28;
  DAT_803aedf4 = 0;
  DAT_803aedf8 = 1;
  DAT_803aedfc = 0;
  DAT_803aecca = uVar2;
  DAT_803dec20 = DAT_803aee0c;
  FUN_802464dc((undefined4 *)&DAT_803debe8);
  uVar2 = DAT_cc002030;
  DAT_cc002030 = uVar2 & 0x7fff;
  uVar2 = DAT_cc002034;
  DAT_cc002034 = uVar2 & 0x7fff;
  DAT_803debf0 = 0;
  DAT_803debf4 = 0;
  FUN_80243ec0(0x18,&LAB_8024c6a4);
  FUN_802442c4(0x80);
  return;
}


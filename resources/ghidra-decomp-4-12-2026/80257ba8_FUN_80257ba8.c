// Function: FUN_80257ba8
// Entry: 80257ba8
// Size: 860 bytes

void FUN_80257ba8(uint param_1,undefined4 param_2,uint param_3,int param_4,uint param_5)

{
  uint *puVar1;
  uint *puVar2;
  int iVar3;
  uint *puVar4;
  
  iVar3 = DAT_803dd210 + param_1 * 4;
  puVar1 = (uint *)(iVar3 + 0x1c);
  puVar2 = (uint *)(iVar3 + 0x3c);
  puVar4 = (uint *)(iVar3 + 0x5c);
  switch(param_2) {
  case 9:
    *puVar1 = *puVar1 & 0xfffffffe | param_3;
    *puVar1 = *puVar1 & 0xfffffff1 | param_4 << 1;
    *puVar1 = *puVar1 & 0xfffffe0f | (param_5 & 0xff) << 4;
    break;
  case 10:
  case 0x19:
    *puVar1 = *puVar1 & 0xffffe3ff | param_4 << 10;
    if (param_3 == 2) {
      *puVar1 = *puVar1 & 0xfffffdff | 0x200;
      *puVar1 = *puVar1 & 0x7fffffff | 0x80000000;
    }
    else {
      *puVar1 = *puVar1 & 0xfffffdff | param_3 << 9;
      *puVar1 = *puVar1 & 0x7fffffff;
    }
    break;
  case 0xb:
    *puVar1 = *puVar1 & 0xffffdfff | param_3 << 0xd;
    *puVar1 = *puVar1 & 0xfffe3fff | param_4 << 0xe;
    break;
  case 0xc:
    *puVar1 = *puVar1 & 0xfffdffff | param_3 << 0x11;
    *puVar1 = *puVar1 & 0xffe3ffff | param_4 << 0x12;
    break;
  case 0xd:
    *puVar1 = *puVar1 & 0xffdfffff | param_3 << 0x15;
    *puVar1 = *puVar1 & 0xfe3fffff | param_4 << 0x16;
    *puVar1 = *puVar1 & 0xc1ffffff | param_5 << 0x19;
    break;
  case 0xe:
    *puVar2 = *puVar2 & 0xfffffffe | param_3;
    *puVar2 = *puVar2 & 0xfffffff1 | param_4 << 1;
    *puVar2 = *puVar2 & 0xfffffe0f | (param_5 & 0xff) << 4;
    break;
  case 0xf:
    *puVar2 = *puVar2 & 0xfffffdff | param_3 << 9;
    *puVar2 = *puVar2 & 0xffffe3ff | param_4 << 10;
    *puVar2 = *puVar2 & 0xfffc1fff | (param_5 & 0xff) << 0xd;
    break;
  case 0x10:
    *puVar2 = *puVar2 & 0xfffbffff | param_3 << 0x12;
    *puVar2 = *puVar2 & 0xffc7ffff | param_4 << 0x13;
    *puVar2 = *puVar2 & 0xf83fffff | (param_5 & 0xff) << 0x16;
    break;
  case 0x11:
    *puVar2 = *puVar2 & 0xf7ffffff | param_3 << 0x1b;
    *puVar2 = *puVar2 & 0x8fffffff | param_4 << 0x1c;
    *puVar4 = *puVar4 & 0xffffffe0 | param_5 & 0xff;
    break;
  case 0x12:
    *puVar4 = *puVar4 & 0xffffffdf | param_3 << 5;
    *puVar4 = *puVar4 & 0xfffffe3f | param_4 << 6;
    *puVar4 = *puVar4 & 0xffffc1ff | (param_5 & 0xff) << 9;
    break;
  case 0x13:
    *puVar4 = *puVar4 & 0xffffbfff | param_3 << 0xe;
    *puVar4 = *puVar4 & 0xfffc7fff | param_4 << 0xf;
    *puVar4 = *puVar4 & 0xff83ffff | (param_5 & 0xff) << 0x12;
    break;
  case 0x14:
    *puVar4 = *puVar4 & 0xff7fffff | param_3 << 0x17;
    *puVar4 = *puVar4 & 0xf8ffffff | param_4 << 0x18;
    *puVar4 = param_5 << 0x1b | *puVar4 & 0x7ffffff;
  }
  *(uint *)(DAT_803dd210 + 0x4f4) = *(uint *)(DAT_803dd210 + 0x4f4) | 0x10;
  *(byte *)(DAT_803dd210 + 0x4f2) = *(byte *)(DAT_803dd210 + 0x4f2) | (byte)(1 << (param_1 & 0xff));
  return;
}


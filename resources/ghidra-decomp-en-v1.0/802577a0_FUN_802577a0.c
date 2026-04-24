// Function: FUN_802577a0
// Entry: 802577a0
// Size: 892 bytes

void FUN_802577a0(uint param_1,int *param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  uint *puVar5;
  uint *puVar6;
  
  iVar2 = DAT_803dc5a8 + param_1 * 4;
  puVar4 = (uint *)(iVar2 + 0x1c);
  puVar5 = (uint *)(iVar2 + 0x3c);
  puVar6 = (uint *)(iVar2 + 0x5c);
  for (; *param_2 != 0xff; param_2 = param_2 + 4) {
    uVar3 = (uint)*(byte *)(param_2 + 3);
    iVar2 = param_2[2];
    uVar1 = param_2[1];
    switch(*param_2) {
    case 9:
      *puVar4 = *puVar4 & 0xfffffffe | uVar1;
      *puVar4 = *puVar4 & 0xfffffff1 | iVar2 << 1;
      *puVar4 = *puVar4 & 0xfffffe0f | uVar3 << 4;
      break;
    case 10:
    case 0x19:
      *puVar4 = *puVar4 & 0xffffe3ff | iVar2 << 10;
      if (uVar1 == 2) {
        *puVar4 = *puVar4 & 0xfffffdff | 0x200;
        *puVar4 = *puVar4 & 0x7fffffff | 0x80000000;
      }
      else {
        *puVar4 = *puVar4 & 0xfffffdff | uVar1 << 9;
        *puVar4 = *puVar4 & 0x7fffffff;
      }
      break;
    case 0xb:
      *puVar4 = *puVar4 & 0xffffdfff | uVar1 << 0xd;
      *puVar4 = *puVar4 & 0xfffe3fff | iVar2 << 0xe;
      break;
    case 0xc:
      *puVar4 = *puVar4 & 0xfffdffff | uVar1 << 0x11;
      *puVar4 = *puVar4 & 0xffe3ffff | iVar2 << 0x12;
      break;
    case 0xd:
      *puVar4 = *puVar4 & 0xffdfffff | uVar1 << 0x15;
      *puVar4 = *puVar4 & 0xfe3fffff | iVar2 << 0x16;
      *puVar4 = *puVar4 & 0xc1ffffff | uVar3 << 0x19;
      break;
    case 0xe:
      *puVar5 = *puVar5 & 0xfffffffe | uVar1;
      *puVar5 = *puVar5 & 0xfffffff1 | iVar2 << 1;
      *puVar5 = *puVar5 & 0xfffffe0f | uVar3 << 4;
      break;
    case 0xf:
      *puVar5 = *puVar5 & 0xfffffdff | uVar1 << 9;
      *puVar5 = *puVar5 & 0xffffe3ff | iVar2 << 10;
      *puVar5 = *puVar5 & 0xfffc1fff | uVar3 << 0xd;
      break;
    case 0x10:
      *puVar5 = *puVar5 & 0xfffbffff | uVar1 << 0x12;
      *puVar5 = *puVar5 & 0xffc7ffff | iVar2 << 0x13;
      *puVar5 = *puVar5 & 0xf83fffff | uVar3 << 0x16;
      break;
    case 0x11:
      *puVar5 = *puVar5 & 0xf7ffffff | uVar1 << 0x1b;
      *puVar5 = *puVar5 & 0x8fffffff | iVar2 << 0x1c;
      *puVar6 = *puVar6 & 0xffffffe0 | uVar3;
      break;
    case 0x12:
      *puVar6 = *puVar6 & 0xffffffdf | uVar1 << 5;
      *puVar6 = *puVar6 & 0xfffffe3f | iVar2 << 6;
      *puVar6 = *puVar6 & 0xffffc1ff | uVar3 << 9;
      break;
    case 0x13:
      *puVar6 = *puVar6 & 0xffffbfff | uVar1 << 0xe;
      *puVar6 = *puVar6 & 0xfffc7fff | iVar2 << 0xf;
      *puVar6 = *puVar6 & 0xff83ffff | uVar3 << 0x12;
      break;
    case 0x14:
      *puVar6 = *puVar6 & 0xff7fffff | uVar1 << 0x17;
      *puVar6 = *puVar6 & 0xf8ffffff | iVar2 << 0x18;
      *puVar6 = uVar3 << 0x1b | *puVar6 & 0x7ffffff;
    }
  }
  *(uint *)(DAT_803dc5a8 + 0x4f4) = *(uint *)(DAT_803dc5a8 + 0x4f4) | 0x10;
  *(byte *)(DAT_803dc5a8 + 0x4f2) = *(byte *)(DAT_803dc5a8 + 0x4f2) | (byte)(1 << (param_1 & 0xff));
  return;
}


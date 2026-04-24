// Function: FUN_802bbcdc
// Entry: 802bbcdc
// Size: 716 bytes

void FUN_802bbcdc(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  short *psVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  undefined8 uVar6;
  undefined4 local_28 [10];
  
  uVar6 = FUN_802860dc();
  psVar2 = (short *)((ulonglong)uVar6 >> 0x20);
  local_28[0] = DAT_803e8230;
  *psVar2 = (short)((int)*(char *)((int)uVar6 + 0x18) << 8);
  *(code **)(psVar2 + 0x5e) = FUN_802bacc0;
  FUN_80037200(psVar2,10);
  iVar5 = *(int *)(psVar2 + 0x5c);
  *(undefined *)(iVar5 + 0xa8c) = *(undefined *)((int)uVar6 + 0x19);
  *(undefined2 *)(iVar5 + 0xa86) = 5;
  *(undefined2 *)(iVar5 + 0xa88) = 1000;
  iVar3 = *(int *)(psVar2 + 0x32);
  if (iVar3 != 0) {
    *(uint *)(iVar3 + 0x30) = *(uint *)(iVar3 + 0x30) | 0xa10;
  }
  if (*(int *)(psVar2 + 0x2a) != 0) {
    *(undefined2 *)(*(int *)(psVar2 + 0x2a) + 0xb2) = 9;
  }
  (**(code **)(*DAT_803dca8c + 4))(psVar2,iVar5,0xc,1);
  *(float *)(iVar5 + 0x2a4) = FLOAT_803e82b8;
  iVar3 = iVar5 + 4;
  *(undefined *)(iVar5 + 0x25f) = 0;
  bVar1 = *(byte *)(iVar5 + 0xa8c);
  if (bVar1 != 2) {
    if (bVar1 < 2) {
      if (bVar1 == 0) goto LAB_802bbe6c;
    }
    else if (4 < bVar1) goto LAB_802bbe6c;
    (**(code **)(*DAT_803dcaa8 + 4))(iVar3,3,0x200020,1);
    (**(code **)(*DAT_803dcaa8 + 8))(iVar3,2,&DAT_80335110,&DAT_803dc734,8);
    (**(code **)(*DAT_803dcaa8 + 0xc))(iVar3,4,&DAT_803350d0,&DAT_80335100,local_28);
    (**(code **)(*DAT_803dcaa8 + 0x20))(psVar2,iVar3);
  }
LAB_802bbe6c:
  FUN_80114f64(psVar2,iVar5 + 0x35c,0xffffe000,0x2aaa,3);
  *(byte *)(iVar5 + 0x96d) = *(byte *)(iVar5 + 0x96d) | 8;
  if (param_3 == 0) {
    cVar4 = -1;
    bVar1 = *(byte *)(iVar5 + 0xa8c);
    if (bVar1 == 3) {
      cVar4 = '\x01';
    }
    else if (bVar1 < 3) {
      if ((bVar1 == 1) && (iVar3 = FUN_8001ffb4(0x16f), iVar3 != 0)) {
        cVar4 = '\0';
      }
    }
    else if ((bVar1 < 5) && (iVar3 = FUN_8001ffb4(0x1db), iVar3 != 0)) {
      cVar4 = '\x02';
    }
    if (-1 < cVar4) {
      iVar5 = cVar4 * 0x24;
      iVar3 = FUN_8001ffb4(*(undefined2 *)(iVar5 + -0x7fccafb2));
      if (iVar3 == 0) {
        *(undefined4 *)(psVar2 + 6) = *(undefined4 *)(iVar5 + -0x7fccafd0);
        *(undefined4 *)(psVar2 + 8) = *(undefined4 *)(iVar5 + -0x7fccafcc);
        *(undefined4 *)(psVar2 + 10) = *(undefined4 *)(iVar5 + -0x7fccafc8);
        *psVar2 = *(short *)(iVar5 + -0x7fccafc4);
      }
      else {
        *(undefined4 *)(psVar2 + 6) = *(undefined4 *)(iVar5 + -0x7fccafc0);
        *(undefined4 *)(psVar2 + 8) = *(undefined4 *)(iVar5 + -0x7fccafbc);
        *(undefined4 *)(psVar2 + 10) = *(undefined4 *)(iVar5 + -0x7fccafb8);
        *psVar2 = *(short *)(iVar5 + -0x7fccafb4);
      }
      iVar3 = FUN_8001ffb4(*(undefined2 *)(iVar5 + -0x7fccafb0));
      if (iVar3 != 0) {
        *psVar2 = *psVar2 + -0x8000;
      }
    }
  }
  FUN_80286128();
  return;
}


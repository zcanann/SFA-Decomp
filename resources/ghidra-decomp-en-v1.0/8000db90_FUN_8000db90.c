// Function: FUN_8000db90
// Entry: 8000db90
// Size: 300 bytes

void FUN_8000db90(void)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  ushort *puVar4;
  uint uVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  uVar5 = (uint)(short)(DAT_803dc878 - 1);
  piVar3 = &DAT_80336e90 + uVar5;
  puVar4 = &DAT_80336d90 + uVar5;
  do {
    if ((short)uVar5 < 0) {
LAB_8000dca4:
      FUN_80286128();
      return;
    }
    if ((*piVar3 == iVar1) && (((uint)uVar6 & 0xffff) == (uint)*puVar4)) {
      uVar2 = (uint)DAT_803dc878;
      DAT_803dc878 = (ushort)(uVar2 - 1);
      uVar5 = uVar5 & 0xffff;
      FUN_8028f2cc(&DAT_80336e90 + uVar5,&DAT_80336e90 + uVar5 + 1,
                   ((uVar2 - 1 & 0xffff) - uVar5) * 4 & 0xfffc);
      FUN_8028f2cc(&DAT_80336d90 + uVar5,&DAT_80336d90 + uVar5 + 1,
                   (DAT_803dc878 - uVar5) * 2 & 0xfffe);
      FUN_8028f2cc(&DAT_80336d10 + uVar5,uVar5 + 0x80336d11,DAT_803dc878 - uVar5 & 0xffff);
      FUN_8000b824(iVar1,(uint)uVar6);
      goto LAB_8000dca4;
    }
    piVar3 = piVar3 + -1;
    puVar4 = puVar4 + -1;
    uVar5 = uVar5 - 1;
  } while( true );
}


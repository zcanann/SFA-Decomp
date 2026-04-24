// Function: FUN_80115ff0
// Entry: 80115ff0
// Size: 280 bytes

void FUN_80115ff0(void)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  uint *puVar8;
  double dVar9;
  
  FUN_80286838();
  iVar1 = FUN_80241de8();
  iVar1 = iVar1 + -0x40000;
  iVar5 = 0;
  piVar6 = &DAT_803a5098;
  do {
    *piVar6 = iVar1;
    iVar7 = *piVar6;
    *(undefined4 *)(iVar7 + 0x40) = 0;
    *(undefined *)(iVar7 + 0x48) = 0;
    puVar8 = (uint *)(iVar7 + 0x20);
    FUN_8025aa74(puVar8,iVar7 + 0x60,(uint)*(ushort *)(iVar7 + 10),(uint)*(ushort *)(iVar7 + 0xc),
                 (uint)*(byte *)(iVar7 + 0x16),(uint)*(byte *)(iVar7 + 0x17),
                 (uint)*(byte *)(iVar7 + 0x18),'\0');
    dVar9 = (double)FLOAT_803e2970;
    FUN_8025ace8(dVar9,dVar9,dVar9,puVar8,(uint)*(byte *)(iVar7 + 0x19),
                 (uint)*(byte *)(iVar7 + 0x1a),0,'\0',0);
    FUN_8025ae7c((int)puVar8,iVar7);
    iVar2 = FUN_8025aea4((int)puVar8);
    uVar3 = FUN_8025ae84((int)puVar8);
    uVar4 = FUN_8025ae94((int)puVar8);
    iVar2 = FUN_8025a850(uVar3,uVar4,iVar2,'\0',0);
    *(int *)(iVar7 + 0x44) = iVar2;
    iVar1 = iVar1 + *(int *)(*piVar6 + 0x44) + 0x60;
    piVar6 = piVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 3);
  DAT_803de264 = 0;
  DAT_803de260 = 0;
  FUN_80286884();
  return;
}


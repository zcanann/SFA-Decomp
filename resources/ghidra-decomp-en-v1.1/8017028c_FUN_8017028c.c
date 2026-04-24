// Function: FUN_8017028c
// Entry: 8017028c
// Size: 540 bytes

void FUN_8017028c(void)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  int *piVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar2 = FUN_80286840();
  piVar6 = *(int **)(iVar2 + 0xb8);
  iVar5 = *(int *)(iVar2 + 0x4c);
  if (*(short *)(iVar5 + 0x1c) == 0) {
    uVar3 = FUN_80022264(600,900);
    *(short *)(piVar6 + 0x10) = (short)uVar3;
    uVar3 = FUN_80022264(0xfffffda8,600);
    *(short *)((int)piVar6 + 0x42) = (short)uVar3;
    *(undefined *)((int)piVar6 + 0x71) = 0;
    if (*(int *)(iVar2 + 0x54) != 0) {
      *(undefined2 *)(*(int *)(iVar2 + 0x54) + 0xb2) = 0x101;
    }
    if (*piVar6 == 0) {
      piVar4 = FUN_8001f58c(iVar2,'\x01');
      *piVar6 = (int)piVar4;
      if (*piVar6 != 0) {
        FUN_8001dbf0(*piVar6,2);
        FUN_8001dc18(*piVar6,0);
        dVar7 = (double)FLOAT_803e3fc8;
        FUN_8001de4c(dVar7,dVar7,dVar7,(int *)*piVar6);
        FUN_8001dbd8(*piVar6,1);
        iVar1 = (uint)*(byte *)((int)piVar6 + 0x71) * 3;
        FUN_8001dbb4(*piVar6,(&DAT_803215c8)[iVar1],(&DAT_803215c9)[iVar1],(&DAT_803215ca)[iVar1],0)
        ;
        dVar8 = (double)FLOAT_803e4010;
        FUN_8001dcfc((double)FLOAT_803e3ff0,dVar8,*piVar6);
        iVar1 = (uint)*(byte *)((int)piVar6 + 0x71) * 3;
        FUN_8001d7f4((double)FLOAT_803e4014,dVar8,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar6,0,
                     (uint)(byte)(&DAT_803215c8)[iVar1],(uint)(byte)(&DAT_803215c9)[iVar1],
                     (uint)(byte)(&DAT_803215ca)[iVar1],0x20,in_r9,in_r10);
        FUN_8001d7d8((double)FLOAT_803e4014,*piVar6);
      }
    }
    *(undefined *)(iVar2 + 0x36) = 200;
    iVar1 = 0;
    piVar4 = piVar6;
    do {
      uVar3 = FUN_80022264(0xffff8001,0x7fff);
      *(short *)(piVar4 + 0x12) = (short)uVar3;
      uVar3 = FUN_80022264(0xfffffc00,0x400);
      *(short *)((int)piVar4 + 0x52) = (short)uVar3;
      uVar3 = FUN_80022264(0xffff8001,0x7fff);
      *(short *)(piVar4 + 0x17) = (short)uVar3;
      uVar3 = FUN_80022264(0xfffffc00,0x400);
      *(short *)((int)piVar4 + 0x66) = (short)uVar3;
      piVar4 = (int *)((int)piVar4 + 2);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 5);
    *(code **)(iVar2 + 0xbc) = FUN_8016f624;
    FUN_800372f8(iVar2,2);
    if ((*(short *)(iVar2 + 0x46) != 0x83e) && (*(short *)(iVar5 + 0x1a) != 0)) {
      piVar6[0xf] = (int)FLOAT_803e4018;
    }
  }
  else {
    *(byte *)(piVar6 + 0x1c) = *(byte *)(piVar6 + 0x1c) | 8;
  }
  FUN_8028688c();
  return;
}


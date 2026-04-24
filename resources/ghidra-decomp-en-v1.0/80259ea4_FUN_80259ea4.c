// Function: FUN_80259ea4
// Entry: 80259ea4
// Size: 484 bytes

void FUN_80259ea4(int param_1,uint param_2,int param_3,uint param_4,uint param_5,int param_6,
                 int param_7)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  if (param_1 == 4) {
    iVar3 = 0;
  }
  else {
    iVar3 = param_1;
    if (param_1 == 5) {
      iVar3 = 1;
    }
  }
  if (param_7 == 0) {
    param_6 = 0;
  }
  iVar1 = -param_7 + 2;
  write_volatile_1(DAT_cc008000,0x10);
  write_volatile_4(0xcc008000,iVar3 + 0x100e);
  uVar2 = ((((((((((param_2 & 0xff) << 1 | param_4) & 0xffffffbb | param_3 << 6 |
                 (uint)((param_5 & 1) != 0) * 4) & 0xfffffff7 | (uint)((param_5 & 2) != 0) * 8) &
                0xffffffef | (uint)((param_5 & 4) != 0) * 0x10) & 0xfffff7df |
               (uint)((param_5 & 8) != 0) * 0x20 | (uint)((param_5 & 0x10) != 0) * 0x800) &
              0xffffefff | (uint)((param_5 & 0x20) != 0) * 0x1000) & 0xffffdfff |
            (uint)((param_5 & 0x40) != 0) * 0x2000) & 0xffffbe7f |
            (uint)((param_5 & 0x80) != 0) * 0x4000 | param_6 << 7) & 0xfffffdff |
          (iVar1 - ((uint)(iVar1 == 0) + -param_7 + 1)) * 0x200) & 0xfffffbff |
          (uint)(param_7 != 0) * 0x400;
  write_volatile_4(0xcc008000,uVar2);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 1;
  if (param_1 == 4) {
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1010);
    write_volatile_4(0xcc008000,uVar2);
  }
  else if (param_1 == 5) {
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1011);
    write_volatile_4(0xcc008000,uVar2);
  }
  return;
}


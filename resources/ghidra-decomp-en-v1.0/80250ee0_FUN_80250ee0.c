// Function: FUN_80250ee0
// Entry: 80250ee0
// Size: 24 bytes

undefined4 FUN_80250ee0(void)

{
  undefined2 uVar1;
  undefined2 uVar2;
  
  uVar1 = read_volatile_2(DAT_cc005004);
  uVar2 = read_volatile_2(DAT_cc005006);
  return CONCAT22(uVar1,uVar2);
}


// Function: FUN_8004a724
// Entry: 8004a724
// Size: 468 bytes

void FUN_8004a724(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  byte bStack_48;
  byte local_47;
  byte local_46 [2];
  int local_44;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28 [10];
  
  FUN_80286840();
  FUN_8025e520(&local_2c,local_28,&local_34,&local_30);
  FUN_8025e520(&local_3c,&local_38,&local_44,&local_40);
  uVar1 = countLeadingZeros(local_38 - local_28[0]);
  uVar1 = uVar1 >> 5;
  uVar2 = countLeadingZeros(local_3c - local_2c);
  uVar2 = uVar2 >> 5;
  uVar3 = -(local_40 - local_30) | local_40 - local_30;
  FUN_80256ac8(&bStack_48,&bStack_48,local_46,&local_47,&bStack_48);
  FUN_8007d858();
  if ((uVar2 == 0) && ((int)uVar3 < 0)) {
    FUN_8007d858();
  }
  else if ((uVar1 == 0) && ((uVar2 != 0 && ((int)uVar3 < 0)))) {
    FUN_8007d858();
  }
  else if ((local_47 == 0) && (((uVar1 != 0 && (uVar2 != 0)) && ((int)uVar3 < 0)))) {
    FUN_8007d858();
  }
  else if ((((local_46[0] == 0) || (local_47 == 0)) ||
           ((uVar1 == 0 || ((uVar2 == 0 || (-1 < (int)uVar3)))))) ||
          (-1 < (-(local_44 - local_34) | local_44 - local_34))) {
    FUN_8007d858();
  }
  else {
    FUN_8007d858();
  }
  FUN_8028688c();
  return;
}


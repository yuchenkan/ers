/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#include <lib/lock-common.h>

void m4_ns(assert_lock) (struct eri_lock *lock);
void m4_ns(assert_unlock) (struct eri_lock *lock);

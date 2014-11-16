#pragma once

#define ATOMIC_INC(val) __atomic_add_fetch(&(val), 1, __ATOMIC_SEQ_CST)
#define ATOMIC_DEC(val) __atomic_sub_fetch(&(val), 1, __ATOMIC_SEQ_CST)
#define ATOMIC_SET(val, n) __atomic_store_n(&(val), (n), __ATOMIC_SEQ_CST)
#define ATOMIC_CAS(val, exp, des) __atomic_compare_exchange(&(val), &(exp), &(des),\
    0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)

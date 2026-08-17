#include "TestHarness.hpp"

#ifndef TEEKO_TEST_SUITE
#define TEEKO_TEST_SUITE "Teeko DMA tests"
#endif

int main()
{
    return teeko::test::RunAll(TEEKO_TEST_SUITE);
}

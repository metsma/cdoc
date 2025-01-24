#pragma once

#include "CDOCExport.h"

#include <vector>

using uchar = unsigned char;
using CDOCData = std::vector<uchar>;

#define DISABLE_COPY(Class) \
	Class(const Class &) = delete; \
	Class &operator=(const Class &) = delete;
#define ENABLE_MOVE(Class) \
	Class(Class &&) noexcept= default; \
	Class &operator=(Class &&) noexcept = default;
#define ENABLE_MOVE_D(Class) \
	Class(Class &&other) { std::swap(other.d, d); } \
	Class &operator=(Class &&other) { std::swap(other.d, d); return *this; }

#if __has_include(<swift/bridging>)
#include <swift/bridging>
#endif

#ifndef SWIFT_NONCOPYABLE
#define SWIFT_NONCOPYABLE
#endif

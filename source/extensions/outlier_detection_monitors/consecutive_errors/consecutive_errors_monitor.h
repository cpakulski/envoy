#pragma once

#include "source/extensions/outlier_detection_monitors/common/monitor_base_impl.h"

namespace Envoy {
namespace Extensions {
namespace Outlier {

class ConsecutiveErrorsMonitor : public ExtMonitorBase {
public:
  ConsecutiveErrorsMonitor() = delete;
  ConsecutiveErrorsMonitor(std::string name, uint32_t enforce, uint32_t max)
      : ExtMonitorBase(name, enforce), max_(max) {}
  virtual ~ConsecutiveErrorsMonitor() {}
  virtual bool onError() override;
  virtual void onSuccess() override;
  virtual void onReset() override;

private:
  // counter needs to be thread-safe, as it is accessed by many worker threads.
  std::atomic<uint32_t> counter_{0};
  uint32_t max_;
};

} // namespace Outlier
} // namespace Extensions
} // namespace Envoy
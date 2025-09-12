import re
import numpy as np
import matplotlib.pyplot as plt

# Retrieve execution times, user times and kernel times

# Initialize lists
v1_real_times, v1_user_times, v1_kernel_times = [], [], []
v2_real_times, v2_user_times, v2_kernel_times = [], [], []

def extract_time(file_name, real_time, user_time, kernel_time):
    with open(file_name, "r") as f:
        for line in f:
            real = re.match(r"real\s+([0-9]+\.[0-9]+)", line)
            if real:
                real_time.append(float(real.group(1)))
            
            user = re.match(r"user\s+([0-9]+\.[0-9]+)", line)
            if user:
                user_time.append(float(user.group(1)))
            
            kernel = re.match(r"sys\s+([0-9]+\.[0-9]+)", line)
            if kernel:
                kernel_time.append(float(kernel.group(1)))

# Extract times from both files
extract_time("v1_times.txt", v1_real_times, v1_user_times, v1_kernel_times)
extract_time("v2_times.txt", v2_real_times, v2_user_times, v2_kernel_times)

# Helper function to compute and plot CDF
def plot_cdf(data, label):
    sorted_data = np.sort(data)
    cdf = np.arange(1, len(sorted_data)+1) / len(sorted_data)
    plt.plot(sorted_data, cdf, label=label, linewidth=2)

# 1. Plot CDF of execution (real) times
plt.figure(figsize=(8,6))
plot_cdf(v1_real_times, "version1 (real)")
plot_cdf(v2_real_times, "version2 (real)")
plt.xlabel("Execution Time (seconds)")
plt.ylabel("CDF")
plt.title("CDF of Execution Times")
plt.legend()
plt.grid(True)
plt.show()

# 2. Plot CDFs of user time and kernel time
fig, axes = plt.subplots(1, 2, figsize=(14,6))

# Userspace time
sorted_v1_user = np.sort(v1_user_times)
cdf_v1_user = np.arange(1, len(sorted_v1_user)+1) / len(sorted_v1_user)
sorted_v2_user = np.sort(v2_user_times)
cdf_v2_user = np.arange(1, len(sorted_v2_user)+1) / len(sorted_v2_user)
axes[0].plot(sorted_v1_user, cdf_v1_user, label="version1 (user)", linewidth=2)
axes[0].plot(sorted_v2_user, cdf_v2_user, label="version2 (user)", linewidth=2)
axes[0].set_xlabel("User Time (seconds)")
axes[0].set_ylabel("CDF")
axes[0].set_title("CDF of User Times")
axes[0].legend()
axes[0].grid(True)

# Kernel time
sorted_v1_sys = np.sort(v1_kernel_times)
cdf_v1_sys = np.arange(1, len(sorted_v1_sys)+1) / len(sorted_v1_sys)
sorted_v2_sys = np.sort(v2_kernel_times)
cdf_v2_sys = np.arange(1, len(sorted_v2_sys)+1) / len(sorted_v2_sys)
axes[1].plot(sorted_v1_sys, cdf_v1_sys, label="version1 (sys)", linewidth=2)
axes[1].plot(sorted_v2_sys, cdf_v2_sys, label="version2 (sys)", linewidth=2)
axes[1].set_xlabel("System (Kernel) Time (seconds)")
axes[1].set_ylabel("CDF")
axes[1].set_title("CDF of Kernel Times")
axes[1].legend()
axes[1].grid(True)

plt.suptitle("User and Kernel Time CDFs")
plt.tight_layout()
plt.show()
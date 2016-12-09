/**
 * sexec - Execute commands via SSH
 * Copyright (C) 2016 Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <config.h>
#include <getopt.h>
#include <unistd.h>
#include <pwd.h>

#include <libssh/libssh.h>
#include <libssh/callbacks.h>

#include <climits>
#include <iostream>
#include <cstdio>
#include <memory>
#include <cassert>
#include <cstdlib>
#include <string>
#include <vector>
#include <fstream>
#include <unordered_set>
#include <chrono>
#include <list>
#include <future>
#include <mutex>

static std::mutex g_io_mutex;

std::string FileGetContents(std::string filename) {
  std::ifstream ifs(filename, std::ifstream::binary);
  if (!ifs) {
    throw std::runtime_error("open: " + filename);
  }
  if (!ifs.seekg(0, std::ios_base::end)) {
    throw std::runtime_error("seekg: " + filename);
  }
  auto size = ifs.tellg();
  if (!ifs.seekg(0, std::ios_base::beg)) {
    throw std::runtime_error("seekg: " + filename);
  }
  std::string contents;
  contents.resize(size);
  if (!ifs.read(&contents.front(), size)) {
    throw std::runtime_error("read: " + filename);
  }
  return contents;
}

struct Options {
  void Parse(int argc, char *argv[]) {
    argv0 = argv[0];
    std::string short_opts = "c:df:hp:t:u:H:T:";
    option long_opts[] = {
      { "cmd",       required_argument, nullptr, 'c' },
      { "dedup",     no_argument,       nullptr, 'd' },
      { "file",      required_argument, nullptr, 'f' },
      { "help",      no_argument,       nullptr, 'h' },
      { "parallel",  required_argument, nullptr, 'p' },
      { "timeout",   required_argument, nullptr, 't' },
      { "user",      required_argument, nullptr, 'u' },
      { "host",      required_argument, nullptr, 'H' },
      { "thread",    required_argument, nullptr, 'T' },
      { nullptr,     0,                 nullptr, 0   }
    };
    for (;;) {
      int opt = getopt_long(argc, argv, short_opts.c_str(), long_opts, nullptr);
      if (opt == -1) {
        break;
      }
      switch (opt) {
        case 'c':
          cmd = optarg;
          break;
        case 'd':
          dedup = true;
          break;
        case 'f':
          script_contents = FileGetContents(optarg);
          break;
        case 'h':
          ShowHelp(stdout);
          exit(EXIT_SUCCESS);
          break;
        case 'p':
          parallel = atoi(optarg);
          break;
        case 't':
          timeout = atoi(optarg);
          break;
        case 'u':
          user = optarg;
          break;
        case 'H':
          LoadHostsFromFile(optarg);
          break;
        case 'T':
          num_threads = atoi(optarg);
          break;
        default:
          ShowHelp(stderr);
          exit(EXIT_FAILURE);
      }
    }
    for (; optind < argc; ++optind) {
      hosts.emplace_back(argv[optind]);
    }
    Validate();
  }

  void LoadHostsFromFile(const char *filename) {
    std::istream *is;
    std::unique_ptr<std::ifstream> ifs;
    if (strcmp(filename, "-") == 0) {
      is = &std::cin;
    } else {
      ifs.reset(new std::ifstream(filename));
      if (!*ifs) {
        throw std::runtime_error(std::string("Failed to open ") + filename);
      }
      is = ifs.get();
    }
    std::string line;
    while (std::getline(*is, line)) {
      if (!line.empty() && line.back() == '\n') {
        line.pop_back();
      }
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      if (line.empty()) {
        continue;
      }
      hosts.emplace_back(line);
    }
  }

  void ShowHelp(FILE *out) {
    fprintf(
        out,
        "Usage: %s [OPTION]... [HOST]...\n"
        "\n"
        "Options:\n"
        "  -c, --cmd <CMD>      Execute <CMD>\n"
        "  -d, --dedup          Dedup hosts\n"
        "  -f, --file <FILE>    Execute <FILE>\n"
        "  -h, --help           Show this message\n"
        "  -p, --parallel <N>   Max parallel, 1 by default\n"
        "  -t, --timeout <SEC>  Timeout in seconds per session, -1 by default\n"
        "  -u, --user <USER>    Signed in as <USER>\n"
        "  -H, --host <FILE>    Use the hosts in <FILE>\n"
        "  -T, --threads <N>    Use <N> threads\n",
        argv0.c_str());
  }

  void Validate() {
    if (hosts.empty()) {
      throw std::runtime_error("No host");
    }
    if (user.empty()) {
      auto size = sysconf(_SC_GETPW_R_SIZE_MAX);
      if (size == -1) {
        throw std::runtime_error(
            "Failed to get the size of the buffer for passwd");
      }
      std::unique_ptr<char[]> buf(new char[size]);
      passwd pwd_store;
      passwd *pwd;
      if (getpwuid_r(geteuid(), &pwd_store, buf.get(), size, &pwd)) {
        throw std::runtime_error("Failed to resolve username");
      }
      user = pwd->pw_name;
    }

    if (dedup) {
      std::vector<std::string> filtered;
      filtered.reserve(hosts.size());
      std::unordered_set<std::string> seen;
      for (const auto &host : hosts) {
        if (seen.count(host) != 0) {
          continue;
        }
        filtered.emplace_back(host);
        seen.emplace(host);
      }
      hosts = filtered;
    }

    // Parse shebang
    if (cmd.empty()) {
      if (script_contents.empty()) {
        throw std::runtime_error("No cmd");
      }
      if (script_contents.compare(0, 2, "#!") != 0) {
        throw std::runtime_error("No shebang");
      }
      auto pos = script_contents.find('\n');
      if (pos == std::string::npos) {
        throw std::runtime_error("No shebang");
      }
      cmd = script_contents.substr(2, pos - 2);
      if (!cmd.empty() && cmd.back() == '\r') {
        cmd.pop_back();
      }
      if (cmd.empty()) {
        throw std::runtime_error("No shebang");
      }
      cmd += " /dev/stdin";
    }

    if (timeout == 0) {
      throw std::runtime_error("Zero timeout?");
    } else if (timeout > 0) {
      timeout = timeout * 1000;
    }

    if (parallel == 0) {
      throw std::runtime_error("Zero parallel?");
    }

    if (num_threads <= 0) {
      throw std::runtime_error("No threads?");
    }

    if (static_cast<size_t>(num_threads) > hosts.size()) {
      num_threads = hosts.size();
    }
  }

  const char *GetHost(size_t i) const {
    return hosts[i].c_str();
  }

  std::string argv0;
  std::string cmd;
  std::vector<std::string> hosts;
  std::string user;
  bool dedup = false;
  std::string script_contents;
  int timeout = -1;
  int parallel = 1;
  int num_threads = 1;
};

class Session {
 public:
  Session(const Options &opts, size_t host_index, ssh_event event) :
      opts_(opts), host_index_(host_index), event_(event),
      sess_(ssh_new(), &ssh_free) {
    assert(event_);
    if (!sess_) {
      throw std::bad_alloc();
    }
    int rc = ssh_options_set(sess_.get(), SSH_OPTIONS_HOST, host());
    if (rc != 0) {
      throw std::runtime_error("Set SSH_OPTIONS_HOST: " + std::to_string(rc));
    }
    rc = ssh_options_set(sess_.get(), SSH_OPTIONS_COMPRESSION, "no");
    if (rc != 0) {
      throw std::runtime_error(
          "Set SSH_OPTIONS_COMPRESSION to no: " + std::to_string(rc));
    }
    int no = 0;
    rc = ssh_options_set(sess_.get(), SSH_OPTIONS_STRICTHOSTKEYCHECK, &no);
    if (rc != 0) {
      throw std::runtime_error(
          "Set SSH_OPTIONS_STRICTHOSTKEYCHECK to no: " + std::to_string(rc));
    }
    rc = ssh_options_set(sess_.get(), SSH_OPTIONS_KNOWNHOSTS, "nosuchfile");
    if (rc != 0) {
      throw std::runtime_error(
          "Set SSH_OPTIONS_KNOWNHOSTS to nosuchfile: " + std::to_string(rc));
    }
    ssh_set_blocking(sess_.get(), 0);
    Drive(&Session::Connect);
    start_time_ = std::chrono::steady_clock::now();
  }

  ~Session() {
    ssh_event_remove_session(event_, sess_.get());
    if (chan_) {
      ssh_channel_free(chan_);
    }
  }

  // Should be called until false is returned.
  bool Drive() {
    if (do_) {
      (this->*do_)();
    }
    return do_ != nullptr;
  }

  int exit_status() const { return exit_status_; }
  bool exit_status_set() const { return exit_status_set_; }

  std::string exit_signal() const { return exit_signal_; }
  bool exit_signal_set() const { return exit_signal_set_; }

  const char *host() const { return opts_.GetHost(host_index_); }

  std::chrono::steady_clock::duration GetRemainingTime() const {
    return std::chrono::steady_clock::now() - start_time_;
  }

 private:
  void Drive(void (Session::*cb)()) {
    do_ = cb;
    Drive();
  }

  void AddEvent() {
    int rc = ssh_event_add_session(event_, sess_.get());
    if (rc != SSH_OK) {
      throw std::runtime_error("Add session to event: " + std::to_string(rc));
    }
  }

  void Connect() {
    int rc = ssh_connect(sess_.get());
    if (!added_event_) {
      AddEvent();
      added_event_ = true;
    }
    switch (rc) {
      case SSH_OK:
        rc = ssh_options_set(sess_.get(), SSH_OPTIONS_USER, opts_.user.c_str());
        if (rc) {
          throw std::runtime_error("Set user option: " + std::to_string(rc));
        }
        Drive(&Session::Authenticate);
        break;
      case SSH_AGAIN:
        break;
      default:
        throw std::runtime_error("Connect: " + std::to_string(rc));
    }
  }

  void Authenticate() {
    int rc = ssh_userauth_gssapi(sess_.get());
    switch (rc) {
      case SSH_AUTH_SUCCESS:
        assert(!chan_);
        chan_ = ssh_channel_new(sess_.get());
        if (!chan_) {
          throw std::bad_alloc();
        }
        memset(&cb_, 0, sizeof(cb_));
        ssh_callbacks_init(&cb_);
        cb_.userdata = this;
        cb_.channel_exit_status_function = &OnChannelExitStatus;
        cb_.channel_exit_signal_function = &OnChannelExitSignal;
        rc = ssh_set_channel_callbacks(chan_, &cb_);
        if (rc != 0) {
          throw std::runtime_error(
              "Set channel callbacks: " + std::to_string(rc));
        }
        Drive(&Session::OpenChannel);
        break;
      case SSH_AUTH_AGAIN:
        break;
      default:
        throw std::runtime_error("Authentiate: " + std::to_string(rc));
    }
  }

  void OpenChannel() {
    int rc = ssh_channel_open_session(chan_);
    switch (rc) {
      case SSH_OK:
        Drive(&Session::ExecuteCommand);
        break;
      case SSH_AGAIN:
        break;
      default:
        throw std::runtime_error("OpenChannel: " + std::to_string(rc));
    }
  }

  void ExecuteCommand() {
    int rc = ssh_channel_request_exec(chan_, opts_.cmd.c_str());
    switch (rc) {
      case SSH_OK:
        Drive(&Session::Communicate);
        break;
      case SSH_AGAIN:
        break;
      default:
        throw std::runtime_error("ExecuteCommand: " + std::to_string(rc));
    }
  }

  void Communicate() {
    if (script_contents_offset_ < opts_.script_contents.size()) {
      for (;;) {
        int rc = ssh_channel_write(
            chan_, opts_.script_contents.data() + script_contents_offset_,
            opts_.script_contents.size() - script_contents_offset_);
        if (rc < 0) {
          throw std::runtime_error("Write to channel: " + std::to_string(rc));
        } else if (rc == 0) {
          break;
        }
        script_contents_offset_ += rc;
        if (script_contents_offset_ == opts_.script_contents.size()) {
          rc = ssh_channel_send_eof(chan_);
          if (rc != SSH_OK) {
            throw std::runtime_error("Send EOF: " + std::to_string(rc));
          }
          break;
        }
      }
    }

    for (int is_stderr = 0; is_stderr < 2; ++is_stderr) {
      char buf[LINE_MAX];
      bool loop = true;
      do {
        int rc = ssh_channel_read_nonblocking(chan_, buf, sizeof(buf),
                                              is_stderr);
        switch (rc) {
          case 0:
          case SSH_AGAIN:
          case SSH_EOF:
            loop = false;
            break;
          default:
            if (rc < 0) {
              throw std::runtime_error("Read channel: " + std::to_string(rc));
            }
            buf_[is_stderr].append(buf, rc);
            while (!buf_[is_stderr].empty()) {
              auto pos = buf_[is_stderr].find('\n');
              if (pos == std::string::npos) {
                break;
              }
              FILE *out = is_stderr ? stderr : stdout;
              {
                std::lock_guard<std::mutex> lock(g_io_mutex);
                fprintf(out, "%s ", host());
                fwrite(buf_[is_stderr].data(), pos + 1, 1, out);
              }
              buf_[is_stderr] = buf_[is_stderr].substr(pos + 1);
            }
        }
      } while (loop);
    }

    if (ssh_channel_is_eof(chan_)) {
      for (int is_stderr = 0; is_stderr < 2; ++is_stderr) {
        auto &buf = buf_[is_stderr];
        if (!buf.empty()) {
          FILE *out = is_stderr ? stderr : stdout;
          {
            std::lock_guard<std::mutex> lock(g_io_mutex);
            fprintf(out, "%s ", host());
            fwrite(buf.data(), buf.size(), 1, out);
            fputc('\n', out);
          }
          buf.clear();
        }
      }
      if (exit_status_set_ || exit_signal_set_) {
        Drive(nullptr);
      }
    }
  }

  static void OnChannelExitStatus(ssh_session sess, ssh_channel chan,
                                  int exit_status, void *userdata) {
    Session *sess_ = static_cast<Session *>(userdata);
    sess_->exit_status_ = exit_status;
    sess_->exit_status_set_ = true;
  }

  static void OnChannelExitSignal(
      ssh_session sess, ssh_channel chan, const char *signal, int core,
      const char *errmsg, const char *lang, void *userdata) {
    Session *sess_ = static_cast<Session *>(userdata);
    sess_->exit_signal_ = signal;
    sess_->exit_signal_set_ = true;
  }

  const Options &opts_;
  size_t host_index_;
  ssh_event event_;
  std::unique_ptr<ssh_session_struct, void(*)(ssh_session)> sess_;
  ssh_channel chan_ = nullptr;
  void (Session::*do_)() = nullptr;
  std::string buf_[2];
  bool exit_status_set_ = false;
  int exit_status_ = 0;
  std::string exit_signal_;
  bool exit_signal_set_ = false;
  size_t script_contents_offset_ = 0;
  ssh_channel_callbacks_struct cb_;
  bool added_event_ = false;
  std::chrono::steady_clock::time_point start_time_;
};

class Sexec {
 public:
  Sexec(int argc, char *argv[]) {
    opts_.Parse(argc, argv);
  }

  static void Init() {
    if (ssh_init()) {
      throw std::runtime_error("Init libssh");
    }
  }

  static void Finalize() {
    if (ssh_finalize()) {
      throw std::runtime_error("Finalize libssh");
    }
  }

  void Run() {
    std::vector<std::future<void>> futures;
    futures.reserve(opts_.num_threads);
    size_t end_index = 0;
    for (size_t start_index = 0; start_index < opts_.hosts.size();
         start_index = end_index) {
      end_index = opts_.hosts.size() * (futures.size() + 1) / opts_.num_threads;
      futures.emplace_back(
          std::async(std::launch::async,
                     [=](){ this->Run(start_index, end_index); }));
    }
    for (auto &future : futures) {
      future.wait();
    }
  }

  void Run(size_t start_index, size_t end_index) {
    std::unique_ptr<ssh_event_struct, void(*)(ssh_event)> event(
       ssh_event_new(), &ssh_event_free);
    if (!event) {
      throw std::runtime_error("New event");
    }
    std::list<std::unique_ptr<Session>> sessions;
    size_t host_index = start_index;
    while (host_index < end_index || !sessions.empty()) {
      while ((opts_.parallel < 0 ||
              sessions.size() < static_cast<size_t>(opts_.parallel)) &&
             host_index < end_index) {
        int index = host_index++;
        try {
          sessions.emplace_back(new Session(opts_, index, event.get()));
        } catch (const std::runtime_error &e) {
          std::lock_guard<std::mutex> lock(g_io_mutex);
          fprintf(stderr, "%s %s\n", opts_.GetHost(index), e.what());
        }
      }
      int timeout = -1;
      if (opts_.timeout > 0) {
        while (!sessions.empty()) {
          timeout = std::chrono::duration_cast<
              std::chrono::milliseconds>(
                  sessions.front()->GetRemainingTime()).count();
          if (timeout < 1) {
            std::lock_guard<std::mutex> lock(g_io_mutex);
            fprintf(stderr, "%s timedout\n", sessions.front()->host());
            sessions.pop_front();
          } else {
            break;
          }
        }
        if (timeout == 0) {
          timeout = -1;
        }
      }
      if (sessions.empty()) {
        continue;
      }
      // Workaround a libssh issue:
      // In some cases, ssh_channel_request_exec() returns SSH_AGAIN, but
      // the following ssh_event_dopoll() will block forever.
      if (timeout < 0 || timeout > 1000) {
        timeout = 1000;
      }
      int rc = ssh_event_dopoll(event.get(), timeout);
      if (rc == SSH_AGAIN) {  // Ignore timedout here and check later.
        rc = SSH_OK;
      }
      if (rc != SSH_OK) {
        throw std::runtime_error("ssh_event_dopoll: " + std::to_string(rc));
      }
      for (auto it = sessions.begin(); it != sessions.end(); ) {
        auto &sess = *it;
        try {
          if (!sess->Drive()) {
            if (sess->exit_status_set() &&
                sess->exit_status() != EXIT_SUCCESS) {
              std::lock_guard<std::mutex> lock(g_io_mutex);
              fprintf(stderr, "%s exit_status: %d\n", sess->host(),
                      sess->exit_status());
            }
            if (sess->exit_signal_set()) {
              std::lock_guard<std::mutex> lock(g_io_mutex);
              fprintf(stderr, "%s exit_signal: %s\n", sess->host(),
                      sess->exit_signal().c_str());
            }
            it = sessions.erase(it);
          } else {
            ++it;
          }
        } catch (const std::runtime_error &e) {
          std::lock_guard<std::mutex> lock(g_io_mutex);
          fprintf(stderr, "%s %s\n", sess->host(), e.what());
          it = sessions.erase(it);
        }
      }
    }
  }

 private:
  Options opts_;
};

int main(int argc, char *argv[]) {
  try {
    Sexec::Init();
    Sexec sexec(argc, argv);
    sexec.Run();
    Sexec::Finalize();
  } catch (const std::runtime_error &e) {
    auto size = sysconf(_SC_HOST_NAME_MAX);
    if (size == -1) {
      size = 64;
    }
    ++size;
    std::unique_ptr<char[]> host(new char[size]);
    if (gethostname(host.get(), size)) {
      snprintf(host.get(), size, "localhost");
    }
    std::lock_guard<std::mutex> lock(g_io_mutex);
    fprintf(stderr, "%s %s\n", host.get(), e.what());
    exit(EXIT_FAILURE);
  }
  return EXIT_SUCCESS;
}

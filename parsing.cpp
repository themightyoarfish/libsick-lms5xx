#include "parsing.hpp"

using namespace std;

namespace sick {
TokenBuffer::TokenBuffer(const char *tokens, size_t len, const string &delim) {
  delim_ = delim;
  tokens_copy_.resize(len + 1, '\0');
  memcpy(&tokens_copy_[0], tokens, len);
  cur_tok_ = strtok(&tokens_copy_[0], delim.c_str());
}

bool TokenBuffer::has_next() const { return cur_tok_ != nullptr; }

const char *TokenBuffer::next() {
  const char *ret = cur_tok_;
  cur_tok_ = strtok(nullptr, delim_.c_str());
  return ret;
}

} // namespace sick

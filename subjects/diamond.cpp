#include "typeinfo_trace.hpp"

class Root {
 public:
  Root();
  virtual ~Root();
  virtual void root_vf();
  virtual void root_vfod();
  virtual void root_vfol();
  virtual void root_vfor();
};

Root::Root() { PRINT_TYPEINFO_TRACE(*this); }
Root::~Root() { PRINT_TYPEINFO_TRACE(*this); }
void Root::root_vf() { PRINT_TYPEINFO_TRACE(*this); }
void Root::root_vfod() { PRINT_TYPEINFO_TRACE(*this); }
void Root::root_vfol() { PRINT_TYPEINFO_TRACE(*this); }
void Root::root_vfor() { PRINT_TYPEINFO_TRACE(*this); }

class Left : public Root {
 public:
  Left();
  ~Left() override;
  virtual void left_vfo();
};
Left::Left() { PRINT_TYPEINFO_TRACE(*this); }
Left::~Left() { PRINT_TYPEINFO_TRACE(*this); }
void Left::left_vfo() { PRINT_TYPEINFO_TRACE(*this); }

class Right : public Root {
 public:
  Right();
  ~Right() override;
  virtual void right_vfo();
};
Right::Right() { PRINT_TYPEINFO_TRACE(*this); }
Right::~Right() { PRINT_TYPEINFO_TRACE(*this); }
void Right::right_vfo() { PRINT_TYPEINFO_TRACE(*this); }

class Diamond : public Left, public Right {
 public:
  Diamond();
  ~Diamond() override;
  void left_vfo() override;
  void right_vfo() override;
};
Diamond::Diamond() { PRINT_TYPEINFO_TRACE(*this); }
Diamond::~Diamond() { PRINT_TYPEINFO_TRACE(*this); }
void Diamond::left_vfo() { PRINT_TYPEINFO_TRACE(*this); }
void Diamond::right_vfo() { PRINT_TYPEINFO_TRACE(*this); }

int main() {
  Diamond d;
  Right &right = d;
  Right *r2 = new Diamond{};
  d.right_vfo();
  d.left_vfo();
  right.right_vfo();
  right.root_vfor();
  r2->root_vfor();
  r2->right_vfo();
  return 0;
}

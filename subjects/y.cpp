#include "typeinfo_trace.hpp"

class Left {
 public:
  Left();
  virtual ~Left();
  virtual void left_vfo();
  virtual void left_vf();

  int left_data{};
};
Left::Left() { PRINT_TYPEINFO_TRACE(*this); }
Left::~Left() { PRINT_TYPEINFO_TRACE(*this); }
void Left::left_vfo() { PRINT_TYPEINFO_TRACE(*this); }
void Left::left_vf() { PRINT_TYPEINFO_TRACE(*this); }

class Right {
 public:
  Right();
  virtual ~Right();
  virtual void right_vfo();
  virtual void right_vf();

  int right_data{};
};
Right::Right() { PRINT_TYPEINFO_TRACE(*this); }
Right::~Right() { PRINT_TYPEINFO_TRACE(*this); }
void Right::right_vfo() { PRINT_TYPEINFO_TRACE(*this); }
void Right::right_vf() { PRINT_TYPEINFO_TRACE(*this); }

class Y : public Left, public Right {
 public:
  Y();
  ~Y() override;
  virtual void y_vf();
  virtual void y_vfo();
  void left_vfo() override;
  void right_vfo() override;
};
Y::Y() { PRINT_TYPEINFO_TRACE(*this); }
Y::~Y() { PRINT_TYPEINFO_TRACE(*this); }
void Y::left_vfo() { PRINT_TYPEINFO_TRACE(*this); }
void Y::right_vfo() { PRINT_TYPEINFO_TRACE(*this); }
void Y::y_vf() { PRINT_TYPEINFO_TRACE(*this); }
void Y::y_vfo() { PRINT_TYPEINFO_TRACE(*this); }

class Yd : public Y {
 public:
  Yd();
  ~Yd() override;
  virtual void yd_vf();
  void y_vfo() override;
  void right_vfo() override;
  void left_vfo() override;
};
Yd::Yd() { PRINT_TYPEINFO_TRACE(*this); }
Yd::~Yd() { PRINT_TYPEINFO_TRACE(*this); }
void Yd::left_vfo() { PRINT_TYPEINFO_TRACE(*this); }
void Yd::right_vfo() { PRINT_TYPEINFO_TRACE(*this); }
void Yd::yd_vf() { PRINT_TYPEINFO_TRACE(*this); }
void Yd::y_vfo() { PRINT_TYPEINFO_TRACE(*this); }

int main() {
  Yd y;
  Right &right = y;
  y.right_vfo();
  y.left_vfo();
  right.right_vfo();
  y.y_vf();
  y.left_vf();
  y.right_vf();
  return 0;
}

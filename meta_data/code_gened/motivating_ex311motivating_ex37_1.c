void motivating_ex311motivating_ex37_1(const char *_op_buf_, char *_op_str_op_(char *, const char *), 
char **_main_argv_, int main_return_, char *copy_return_)
{
  if (!strcmp(_op_buf_, "passwd"))
  {
    printf("##\n");
    char *_copy_dest_;
    _copy_dest_ = sink_data;
    const char *_copy_src_;
    _copy_src_ = "secret";
    {
      copy_return_ = strcpy(_copy_dest_, _copy_src_);
      goto copy_label_;
      copy_label_:
      printf("##\n");

    }
  }

  op_label_:
  printf("##\n");

  dump();
  printf("%s\n", sink_data);
}


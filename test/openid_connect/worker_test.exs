defmodule OpenidConnect.WorkerTest do
  use ExUnit.Case

  test "starting with :ignore does nothing" do
    :ignore = OpenidConnect.Worker.start_link(:ignore)
  end
end

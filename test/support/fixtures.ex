defmodule Fixtures do
  def load(provider, type) do
    response =
      Code.eval_file("test/fixtures/#{provider}/#{type}.exs")
      |> elem(0)
      |> serialize()

    {:ok, response}
  end

  defp serialize(%HTTPoison.Response{body: body} = response), do: %{response | body: Jason.encode!(body)}
  defp serialize(response), do: response
end

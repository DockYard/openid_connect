defmodule OpenIDConnect.Document.CacheTest do
  use ExUnit.Case, async: true
  import OpenIDConnect.Document.Cache

  @valid_document %OpenIDConnect.Document{
    authorization_endpoint: "https://common.auth0.com/authorize",
    claims_supported: [
      "aud",
      "auth_time",
      "created_at",
      "email",
      "email_verified",
      "exp",
      "family_name",
      "given_name",
      "iat",
      "identities",
      "iss",
      "name",
      "nickname",
      "phone_number",
      "picture",
      "sub"
    ],
    end_session_endpoint: nil,
    expires_at: DateTime.utc_now(),
    jwks: %JOSE.JWK{},
    raw: "",
    response_types_supported: [
      "code",
      "token",
      "id_token",
      "code token",
      "code id_token",
      "id_token token",
      "code id_token token"
    ],
    token_endpoint: "https://common.auth0.com/oauth/token"
  }

  describe "put/2" do
    test "persists a documents to the cache" do
      uri = uniq_uri()
      document = %{@valid_document | expires_at: DateTime.utc_now() |> DateTime.add(60, :second)}

      put(uri, document)

      assert %{^uri => {_ref, _last_fetched_at, ^document}} = flush()
    end

    test "does not persist expired documents" do
      uri = uniq_uri()
      document = %{@valid_document | expires_at: DateTime.utc_now() |> DateTime.add(-60, :second)}

      put(uri, document)

      refute Map.has_key?(flush(), uri)
    end

    test "schedules document removal and removes it once it's expired" do
      uri = uniq_uri()
      document = %{@valid_document | expires_at: DateTime.utc_now() |> DateTime.add(60, :second)}

      put(uri, document)

      assert %{^uri => {ref, _last_fetched_at, _document}} = flush()
      assert Process.read_timer(ref) in 58_000..62_000

      send(OpenIDConnect.Document.Cache, {:remove, uri})
      refute Map.has_key?(flush(), uri)
    end
  end

  describe "fetch/1" do
    test "returns error when there is no cache" do
      uri = uniq_uri()
      assert fetch(uri) == :error
    end

    test "returns cached documents" do
      uri = uniq_uri()
      document = %{@valid_document | expires_at: DateTime.utc_now() |> DateTime.add(60, :second)}
      put(uri, document)

      assert {:ok, cached_document} = fetch(uri)
      assert document == cached_document
    end

    test "does not return documents that already expired" do
      uri = uniq_uri()
      now = DateTime.utc_now()
      document = %{@valid_document | expires_at: DateTime.add(now, -1, :second)}
      state = %{uri => {nil, now, document}}

      assert handle_call({:fetch, uri}, self(), state) == {:reply, :error, %{}}
    end
  end

  describe ":gc" do
    test "doesn't do anything when cache is empty" do
      {:ok, pid} = start_link(name: :gc_test1)
      assert Enum.empty?(flush(pid))
      send(pid, :gc)
      assert flush(pid) == %{}
    end

    test "removes excessive entries from cache" do
      {:ok, pid} = start_link(name: :gc_test2)

      documents =
        for i <- 1..2000 do
          expires_at = DateTime.utc_now() |> DateTime.add(60 + i, :second)
          document = %{@valid_document | expires_at: expires_at}
          put(pid, uniq_uri(), document)
          document
        end

      assert Enum.count(flush(pid)) == 2000

      send(pid, :gc)

      assert state = flush(pid)
      assert Enum.count(state) == 1000

      {_uri, {_ref, _last_fetched_at, document}} =
        Enum.min_by(
          state,
          fn {_uri, {_ref, last_fetched_at, _document}} ->
            last_fetched_at
          end,
          DateTime
        )

      assert document.expires_at == Enum.at(documents, 1000).expires_at
    end
  end

  defp uniq_uri, do: "http://example.com:#{System.unique_integer([:positive])}"
end

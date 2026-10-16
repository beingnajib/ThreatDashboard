import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";

import { Loading } from "./components/Feedback";
import Layout from "./components/Layout";
import { useAuth } from "./lib/auth";
import Login from "./pages/Login";

const Overview = lazy(() => import("./pages/Overview"));
const Executive = lazy(() => import("./pages/Executive"));
const Incidents = lazy(() => import("./pages/Incidents"));
const IncidentDetail = lazy(() => import("./pages/IncidentDetail"));
const Alerts = lazy(() => import("./pages/Alerts"));
const Indicators = lazy(() => import("./pages/Indicators"));
const Telemetry = lazy(() => import("./pages/Telemetry"));
const Assets = lazy(() => import("./pages/Assets"));
const Actors = lazy(() => import("./pages/Actors"));
const Exposure = lazy(() => import("./pages/Exposure"));
const Feeds = lazy(() => import("./pages/Feeds"));
const Import = lazy(() => import("./pages/Import"));
const Response = lazy(() => import("./pages/Response"));
const Rules = lazy(() => import("./pages/Rules"));
const Compliance = lazy(() => import("./pages/Compliance"));
const Reports = lazy(() => import("./pages/Reports"));
const Query = lazy(() => import("./pages/Query"));

export default function App() {
  const { user, loading } = useAuth();
  if (loading) return <Loading label="Restoring session" />;
  if (!user) return <Login />;
  return (
    <Suspense fallback={<Loading />}>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="executive" element={<Executive />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="incidents/:id" element={<IncidentDetail />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="indicators" element={<Indicators />} />
          <Route path="telemetry" element={<Telemetry />} />
          <Route path="assets" element={<Assets />} />
          <Route path="actors" element={<Actors />} />
          <Route path="exposure" element={<Exposure />} />
          <Route path="feeds" element={<Feeds />} />
          <Route path="import" element={<Import />} />
          <Route path="response" element={<Response />} />
          <Route path="rules" element={<Rules />} />
          <Route path="compliance" element={<Compliance />} />
          <Route path="reports" element={<Reports />} />
          <Route path="query" element={<Query />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Suspense>
  );
}

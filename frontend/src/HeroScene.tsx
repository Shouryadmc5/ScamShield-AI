import { useEffect, useMemo, useRef } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import {
  DoubleSide,
  ExtrudeGeometry,
  MathUtils,
  MeshBasicMaterial,
  Shape,
  Vector2,
} from 'three';
import type { Group, Mesh } from 'three';

const SIGNALS = [
  { position: [0, 1.78, 0.06] as [number, number, number], color: '#f2774a', scale: 0.06 },
  { position: [-1.65, -0.52, 0.1] as [number, number, number], color: '#85e1df', scale: 0.04 },
  { position: [1.48, 0.92, -0.08] as [number, number, number], color: '#e7d4b7', scale: 0.035 },
];

function Shield() {
  const shieldRef = useRef<Group>(null);
  const beamRef = useRef<Mesh>(null);
  const timeRef = useRef(0);

  const geometry = useMemo(() => {
    const shape = new Shape();
    shape.moveTo(0, 1.35);
    shape.quadraticCurveTo(-0.5, 1.12, -1.05, 0.92);
    shape.lineTo(-0.98, -0.12);
    shape.quadraticCurveTo(-0.84, -0.88, 0, -1.38);
    shape.quadraticCurveTo(0.84, -0.88, 0.98, -0.12);
    shape.lineTo(1.05, 0.92);
    shape.quadraticCurveTo(0.5, 1.12, 0, 1.35);
    return new ExtrudeGeometry(shape, {
      depth: 0.18,
      bevelEnabled: true,
      bevelSegments: 4,
      steps: 1,
      bevelSize: 0.055,
      bevelThickness: 0.045,
      curveSegments: 10,
    });
  }, []);
  const innerShape = useMemo(() => new Shape([
    new Vector2(0, 0.76),
    new Vector2(0.52, 0.52),
    new Vector2(0.48, -0.08),
    new Vector2(0, -0.82),
    new Vector2(-0.48, -0.08),
    new Vector2(-0.52, 0.52),
  ]), []);

  useFrame(({ pointer }, delta) => {
    timeRef.current += delta;
    const time = timeRef.current;
    if (shieldRef.current) {
      shieldRef.current.rotation.y = MathUtils.damp(
        shieldRef.current.rotation.y,
        pointer.x * 0.18 + Math.sin(time * 0.35) * 0.07,
        3,
        delta,
      );
      shieldRef.current.rotation.x = MathUtils.damp(
        shieldRef.current.rotation.x,
        -pointer.y * 0.1,
        3,
        delta,
      );
      shieldRef.current.position.y = Math.sin(time * 0.7) * 0.045;
    }
    if (beamRef.current) {
      beamRef.current.position.y = Math.sin(time * 0.65) * 0.92;
      if (beamRef.current.material instanceof MeshBasicMaterial) {
        beamRef.current.material.opacity = 0.46 + Math.sin(time * 0.65) * 0.12;
      }
    }
  });

  return (
    <group>
      <mesh rotation={[0.08, 0, 0]} scale={1.62}>
        <torusGeometry args={[1.08, 0.003, 6, 88]} />
        <meshBasicMaterial color="#6ccbd1" transparent opacity={0.42} />
      </mesh>
      <mesh rotation={[0.72, 0.35, 0.2]} scale={1.94}>
        <torusGeometry args={[1.08, 0.0025, 6, 88]} />
        <meshBasicMaterial color="#fa6938" transparent opacity={0.58} />
      </mesh>
      <group ref={shieldRef} rotation={[0, -0.24, -0.06]}>
        <mesh geometry={geometry} position={[0, 0, -0.09]}>
          <meshPhysicalMaterial
            color="#8ddce0"
            emissive="#13565c"
            emissiveIntensity={0.38}
            metalness={0.18}
            roughness={0.18}
            transmission={0.52}
            thickness={0.7}
            transparent
            opacity={0.76}
            side={DoubleSide}
          />
        </mesh>
        <mesh position={[0, 0, 0.15]}>
          <shapeGeometry args={[innerShape]} />
          <meshBasicMaterial color="#091315" transparent opacity={0.38} side={DoubleSide} />
        </mesh>
        <mesh ref={beamRef} position={[0, 0, 0.18]}>
          <boxGeometry args={[1.64, 0.012, 0.018]} />
          <meshBasicMaterial color="#96f0e8" transparent opacity={0.55} />
        </mesh>
        <mesh position={[0, -0.02, 0.19]}>
          <torusGeometry args={[0.19, 0.014, 8, 32, Math.PI]} />
          <meshBasicMaterial color="#f2774a" transparent opacity={0.9} />
        </mesh>
      </group>
      <OrbitSignals />
    </group>
  );
}

function OrbitSignals() {
  const orbitRef = useRef<Group>(null);
  const timeRef = useRef(0);
  useFrame((_, delta) => {
    timeRef.current += delta;
    if (orbitRef.current) orbitRef.current.rotation.z = timeRef.current * 0.075;
  });
  return (
    <group ref={orbitRef}>
      {SIGNALS.map((signal) => (
        <mesh key={signal.position.join(',')} position={signal.position} scale={signal.scale}>
          <icosahedronGeometry args={[1, 1]} />
          <meshBasicMaterial color={signal.color} />
        </mesh>
      ))}
    </group>
  );
}

function FrameDriver() {
  const canvas = useThree((state) => state.gl.domElement);
  const invalidate = useThree((state) => state.invalidate);

  useEffect(() => {
    let isIntersecting = false;
    let interval: number | undefined;
    const refresh = () => {
      if (interval !== undefined) window.clearInterval(interval);
      if (isIntersecting && !document.hidden) {
        invalidate();
        interval = window.setInterval(invalidate, 1000 / 30);
      }
    };
    const observer = new IntersectionObserver(([entry]) => {
      isIntersecting = entry.isIntersecting;
      refresh();
    });
    observer.observe(canvas);
    document.addEventListener('visibilitychange', refresh);

    return () => {
      observer.disconnect();
      document.removeEventListener('visibilitychange', refresh);
      if (interval !== undefined) window.clearInterval(interval);
    };
  }, [canvas, invalidate]);

  return null;
}

export default function HeroScene() {
  return (
    <Canvas
      className="hero-canvas"
      dpr={window.matchMedia('(max-width: 640px)').matches ? 1 : [1, 1.35]}
      camera={{ position: [0, 0, 5.4], fov: 38 }}
      gl={{ alpha: true, antialias: true, powerPreference: 'low-power' }}
      frameloop="demand"
      fallback={<div className="static-shield" aria-hidden="true"><span>◇</span></div>}
      aria-hidden="true"
    >
      <ambientLight intensity={0.8} />
      <pointLight position={[3, 2, 4]} color="#75e4e0" intensity={34} />
      <pointLight position={[-3, -2, 2]} color="#f26e43" intensity={20} />
      <FrameDriver />
      <Shield />
    </Canvas>
  );
}
